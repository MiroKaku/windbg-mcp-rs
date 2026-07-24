use std::{
    collections::BTreeSet,
    env,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process,
    sync::{Arc, Condvar, LazyLock, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::Router;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use windows::{
    Win32::{
        Foundation::ERROR_SHARING_VIOLATION,
        Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
        System::Diagnostics::Debug::Extensions::{
            DEBUG_CONNECT_SESSION_NO_ANNOUNCE, DEBUG_CONNECT_SESSION_NO_VERSION,
            DEBUG_OUTPUT_NORMAL, IDebugControl,
        },
    },
    core::{Interface, PCSTR, PCWSTR},
};

use crate::{
    CommandDispatcher, ExecutionMode, WindbgMcpServer,
    primary_client::create_client_from_primary,
    target_snapshot::{CurrentTargetSnapshot, capture_current_target_snapshot},
};

const DEFAULT_BIND_HOST: &str = "127.0.0.1";
const DEFAULT_BIND_PORT: u16 = 50051;
const AUTO_BIND_PORT_COUNT: u16 = 20;
const FILE_SHARE_READ: u32 = 0x00000001;
const TARGET_SNAPSHOT_INITIAL_DELAY_MS: u64 = 750;
const TARGET_SNAPSHOT_RETRY_DELAY_MS: u64 = 1000;
const TARGET_SNAPSHOT_MAX_ATTEMPTS: usize = 6;
const STOP_DURING_COMMAND_ERROR: &str = "Cannot stop WinDbg MCP server while an MCP command is executing. Wait for the command to finish and run !mcp stop again.";
const EXECUTION_UNAVAILABLE_ERROR: &str =
    "MCP server is stopping; debugger execution is unavailable.";

static SERVER_STATE: LazyLock<Mutex<Option<RunningPluginServer>>> =
    LazyLock::new(|| Mutex::new(None));
static DISPATCHER_STATE: LazyLock<Mutex<Option<CommandDispatcher>>> =
    LazyLock::new(|| Mutex::new(None));
static EXECUTION_GATE: LazyLock<McpExecutionGate> = LazyLock::new(McpExecutionGate::new);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpExecutionPhase {
    Stopped,
    Running,
    Stopping,
}

#[derive(Debug)]
struct McpExecutionGateState {
    phase: McpExecutionPhase,
    active: usize,
}

struct McpExecutionGate {
    state: Mutex<McpExecutionGateState>,
    wake: Condvar,
}

pub(crate) struct McpExecutionGuard<'a> {
    gate: &'a McpExecutionGate,
}

impl Drop for McpExecutionGuard<'_> {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active > 0 {
            state.active -= 1;
        }
        self.gate.wake.notify_all();
    }
}

#[derive(Debug, Clone)]
pub struct PluginServerStatus {
    pub mcp_url: String,
    pub registry_path: Option<PathBuf>,
}

struct RunningPluginServer {
    status: PluginServerStatus,
    cancellation: CancellationToken,
    join_handle: JoinHandle<()>,
    registry: Option<InstanceRegistry>,
    session_state: SessionState,
    session_generation: u64,
    snapshot_worker: Option<SnapshotWorker>,
}

struct InstanceRegistry {
    writer: InstanceRegistryWriter,
    lock_path: PathBuf,
    lock_file: File,
}

struct InstanceRegistryWriter {
    path: PathBuf,
    base_payload: InstanceRegistryBasePayload,
}

struct InstanceRegistryBasePayload {
    mcp_server_url: String,
    host_pid: u32,
    host_arch: String,
    host_process_path: Option<String>,
    started_unix_ms: u64,
}

#[derive(Serialize)]
struct InstanceRegistryPayload {
    schema: u32,
    mcp_server_name: &'static str,
    mcp_server_url: String,
    host_pid: u32,
    host_arch: String,
    host_process_path: Option<String>,
    started_unix_ms: u64,
    current_target: Option<CurrentTargetSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionEvent {
    Active,
    Accessible,
    Inaccessible,
    Inactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionState {
    Inactive,
    Inaccessible,
    Accessible,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SessionTransition {
    clear_target: bool,
    capture_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct SnapshotTiming {
    initial_delay: Duration,
    retry_delay: Duration,
    max_attempts: usize,
}

impl Default for SnapshotTiming {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(TARGET_SNAPSHOT_INITIAL_DELAY_MS),
            retry_delay: Duration::from_millis(TARGET_SNAPSHOT_RETRY_DELAY_MS),
            max_attempts: TARGET_SNAPSHOT_MAX_ATTEMPTS,
        }
    }
}

#[derive(Debug, Default)]
struct SnapshotWorkerState {
    requested_generation: Option<u64>,
    shutdown: bool,
}

struct SnapshotWorker {
    state: Arc<(Mutex<SnapshotWorkerState>, Condvar)>,
    join_handle: Option<JoinHandle<()>>,
}

enum SnapshotWorkerWake {
    Requested(u64),
    TimedOut,
    Shutdown,
}

impl SnapshotWorker {
    fn spawn<C, P>(capture: C, publish: P, timing: SnapshotTiming) -> Result<Self, String>
    where
        C: Fn() -> Option<CurrentTargetSnapshot> + Send + 'static,
        P: Fn(u64, &CurrentTargetSnapshot) -> Result<bool, String> + Send + 'static,
    {
        let state = Arc::new((Mutex::new(SnapshotWorkerState::default()), Condvar::new()));
        let worker_state = Arc::clone(&state);
        let join_handle = thread::Builder::new()
            .name("windbg-mcp-target-snapshot".to_string())
            .spawn(move || run_snapshot_worker(&worker_state, &capture, &publish, timing))
            .map_err(|error| error.to_string())?;

        Ok(Self {
            state,
            join_handle: Some(join_handle),
        })
    }

    fn request(&self, generation: u64) -> Result<(), String> {
        let (state, wake) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| "snapshot worker state lock poisoned".to_string())?;
        if state.shutdown {
            return Err("snapshot worker is stopped".to_string());
        }
        state.requested_generation = Some(generation);
        wake.notify_one();
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), String> {
        let (state, wake) = &*self.state;
        {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.shutdown = true;
            wake.notify_all();
        }

        let Some(join_handle) = self.join_handle.take() else {
            return Ok(());
        };
        join_handle
            .join()
            .map_err(|_| "snapshot worker thread panicked".to_string())
    }
}

fn run_snapshot_worker<C, P>(
    state: &Arc<(Mutex<SnapshotWorkerState>, Condvar)>,
    capture: &C,
    publish: &P,
    timing: SnapshotTiming,
) where
    C: Fn() -> Option<CurrentTargetSnapshot>,
    P: Fn(u64, &CurrentTargetSnapshot) -> Result<bool, String>,
{
    let max_attempts = timing.max_attempts.max(1);

    while let Some(mut generation) = wait_for_snapshot_request(state) {
        let mut snapshot = None;
        let mut attempts = 0;
        let mut delay = timing.initial_delay;

        loop {
            match wait_for_snapshot_delay(state, delay) {
                SnapshotWorkerWake::Requested(requested_generation) => {
                    generation = requested_generation;
                    snapshot = None;
                    attempts = 0;
                    delay = timing.initial_delay;
                    continue;
                }
                SnapshotWorkerWake::TimedOut => {}
                SnapshotWorkerWake::Shutdown => return,
            }

            attempts += 1;
            if snapshot.is_none() {
                snapshot = capture();
            }

            let Some(captured) = snapshot.as_ref() else {
                if attempts >= max_attempts {
                    break;
                }
                delay = timing.retry_delay;
                continue;
            };

            if snapshot_worker_is_shutdown(state) {
                return;
            }

            match publish(generation, captured) {
                Ok(_) => break,
                Err(_) if attempts < max_attempts => {
                    delay = timing.retry_delay;
                }
                Err(_) => break,
            }
        }
    }
}

fn wait_for_snapshot_request(shared: &Arc<(Mutex<SnapshotWorkerState>, Condvar)>) -> Option<u64> {
    let (state, wake) = &**shared;
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while !state.shutdown && state.requested_generation.is_none() {
        state = wake
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }

    if state.shutdown {
        None
    } else {
        state.requested_generation.take()
    }
}

fn wait_for_snapshot_delay(
    shared: &Arc<(Mutex<SnapshotWorkerState>, Condvar)>,
    delay: Duration,
) -> SnapshotWorkerWake {
    let (state, wake) = &**shared;
    let deadline = Instant::now() + delay;
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    loop {
        if state.shutdown {
            return SnapshotWorkerWake::Shutdown;
        }
        if let Some(generation) = state.requested_generation.take() {
            return SnapshotWorkerWake::Requested(generation);
        }

        let now = Instant::now();
        if now >= deadline {
            return SnapshotWorkerWake::TimedOut;
        }

        state = match wake.wait_timeout(state, deadline - now) {
            Ok((state, _)) => state,
            Err(error) => error.into_inner().0,
        };
    }
}

fn snapshot_worker_is_shutdown(shared: &Arc<(Mutex<SnapshotWorkerState>, Condvar)>) -> bool {
    let (state, _) = &**shared;
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .shutdown
}

fn reduce_session_event(
    state: &mut SessionState,
    generation: &mut u64,
    event: SessionEvent,
) -> Result<SessionTransition, String> {
    let mut transition = SessionTransition::default();
    match event {
        SessionEvent::Active if *state == SessionState::Inactive => {
            *generation = generation
                .checked_add(1)
                .ok_or_else(|| "session generation overflow".to_string())?;
            *state = SessionState::Inaccessible;
            transition.clear_target = true;
        }
        SessionEvent::Accessible => {
            if *state != SessionState::Accessible {
                *generation = generation
                    .checked_add(1)
                    .ok_or_else(|| "session generation overflow".to_string())?;
                *state = SessionState::Accessible;
            }
            transition.capture_generation = Some(*generation);
        }
        SessionEvent::Inaccessible if *state == SessionState::Accessible => {
            *generation = generation
                .checked_add(1)
                .ok_or_else(|| "session generation overflow".to_string())?;
            *state = SessionState::Inaccessible;
        }
        SessionEvent::Inactive if *state != SessionState::Inactive => {
            *generation = generation
                .checked_add(1)
                .ok_or_else(|| "session generation overflow".to_string())?;
            *state = SessionState::Inactive;
            transition.clear_target = true;
        }
        SessionEvent::Active | SessionEvent::Inaccessible | SessionEvent::Inactive => {}
    }
    Ok(transition)
}

impl McpExecutionGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(McpExecutionGateState {
                phase: McpExecutionPhase::Stopped,
                active: 0,
            }),
            wake: Condvar::new(),
        }
    }

    fn ensure_startable(&self) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "execution gate state lock poisoned".to_string())?;
        if state.phase == McpExecutionPhase::Stopped {
            Ok(())
        } else {
            Err(EXECUTION_UNAVAILABLE_ERROR.to_string())
        }
    }

    fn mark_running(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "execution gate state lock poisoned".to_string())?;
        if state.phase != McpExecutionPhase::Stopped || state.active != 0 {
            return Err("execution gate was not stopped before server startup".to_string());
        }
        state.phase = McpExecutionPhase::Running;
        self.wake.notify_all();
        Ok(())
    }

    fn begin_execution(&self) -> Result<McpExecutionGuard<'_>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "execution gate state lock poisoned".to_string())?;
        if state.phase != McpExecutionPhase::Running {
            return Err(EXECUTION_UNAVAILABLE_ERROR.to_string());
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| "active MCP execution counter overflow".to_string())?;
        Ok(McpExecutionGuard { gate: self })
    }

    fn begin_command_stop(&self) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "execution gate state lock poisoned".to_string())?;
        match state.phase {
            McpExecutionPhase::Stopped => Ok(false),
            McpExecutionPhase::Stopping => Err(EXECUTION_UNAVAILABLE_ERROR.to_string()),
            McpExecutionPhase::Running if state.active > 0 => {
                Err(STOP_DURING_COMMAND_ERROR.to_string())
            }
            McpExecutionPhase::Running => {
                state.phase = McpExecutionPhase::Stopping;
                self.wake.notify_all();
                Ok(true)
            }
        }
    }

    fn begin_unload_stop(&self) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "execution gate state lock poisoned".to_string())?;
        match state.phase {
            McpExecutionPhase::Stopped => return Ok(false),
            McpExecutionPhase::Running => {
                state.phase = McpExecutionPhase::Stopping;
                self.wake.notify_all();
            }
            McpExecutionPhase::Stopping => {
                while state.phase == McpExecutionPhase::Stopping {
                    state = self
                        .wake
                        .wait(state)
                        .map_err(|_| "execution gate state lock poisoned".to_string())?;
                }
                return Ok(false);
            }
        }

        while state.active > 0 {
            state = self
                .wake
                .wait(state)
                .map_err(|_| "execution gate state lock poisoned".to_string())?;
        }
        Ok(true)
    }

    fn restore_running(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase == McpExecutionPhase::Stopping {
            state.phase = McpExecutionPhase::Running;
        }
        self.wake.notify_all();
    }

    fn finish_stopped(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.phase = McpExecutionPhase::Stopped;
        state.active = 0;
        self.wake.notify_all();
    }

    #[cfg(test)]
    fn phase(&self) -> McpExecutionPhase {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .phase
    }
}

pub struct PluginServerControl;

impl PluginServerControl {
    pub fn get_or_start_dispatcher() -> Result<CommandDispatcher, String> {
        let existing = {
            let state = DISPATCHER_STATE
                .lock()
                .map_err(|_| "dispatcher state lock poisoned".to_string())?;
            state.clone()
        };

        if let Some(dispatcher) = existing {
            return Ok(dispatcher);
        }

        match CommandDispatcher::spawn(ExecutionMode::CurrentSession) {
            Ok(dispatcher) => {
                let mut state = DISPATCHER_STATE
                    .lock()
                    .map_err(|_| "dispatcher state lock poisoned".to_string())?;
                if let Some(existing) = state.as_ref() {
                    return Ok(existing.clone());
                }
                let cloned = dispatcher.clone();
                *state = Some(dispatcher);
                Ok(cloned)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn start(bind_address: Option<&str>) -> Result<PluginServerStatus, String> {
        let bind_addresses = bind_address_candidates(bind_address);

        {
            let state = SERVER_STATE
                .lock()
                .map_err(|_| "server state lock poisoned".to_string())?;
            if let Some(existing) = state.as_ref() {
                return Ok(existing.status.clone());
            }
        }
        EXECUTION_GATE.ensure_startable()?;
        let mut state = SERVER_STATE
            .lock()
            .map_err(|_| "server state lock poisoned".to_string())?;
        if let Some(existing) = state.as_ref() {
            return Ok(existing.status.clone());
        }

        let cancellation = CancellationToken::new();
        let cancellation_for_thread = cancellation.clone();
        let (startup_tx, startup_rx) = mpsc::channel::<Result<PluginServerStatus, String>>();
        let thread_bind_addresses = bind_addresses.clone();

        let join_handle = thread::Builder::new()
            .name("windbg-mcp-plugin-server".to_string())
            .spawn(move || {
                let startup_error_tx = startup_tx.clone();
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_tx.send(Err(error.to_string()));
                        return;
                    }
                };

                let result = runtime.block_on(async move {
                    run_server_loop(thread_bind_addresses, cancellation_for_thread, startup_tx)
                        .await
                });

                if let Err(error) = result {
                    let _ = startup_error_tx.send(Err(error.clone()));
                    tracing::error!("plugin MCP server stopped with error: {error}");
                }
            })
            .map_err(|error| error.to_string())?;

        let mut status = match startup_rx.recv() {
            Ok(Ok(status)) => status,
            Ok(Err(error)) => {
                cancellation.cancel();
                let _ = join_handle.join();
                return Err(error);
            }
            Err(_) => {
                cancellation.cancel();
                let _ = join_handle.join();
                return Err("plugin server failed to report startup status".to_string());
            }
        };

        let _ = cleanup_stale_instance_registries();
        let registry = write_instance_registry(&status).ok();
        status.registry_path = registry
            .as_ref()
            .map(|registry| registry.writer.path.clone());

        let snapshot_worker = match SnapshotWorker::spawn(
            capture_current_target_snapshot,
            publish_target_snapshot,
            SnapshotTiming::default(),
        ) {
            Ok(worker) => worker,
            Err(error) => {
                cancellation.cancel();
                let _ = join_handle.join();
                if let Some(registry) = registry {
                    remove_instance_registry(registry);
                }
                return Err(error);
            }
        };

        *state = Some(RunningPluginServer {
            status: status.clone(),
            cancellation,
            join_handle,
            registry,
            session_state: SessionState::Inactive,
            session_generation: 0,
            snapshot_worker: Some(snapshot_worker),
        });
        drop(state);
        if let Err(error) = EXECUTION_GATE.mark_running() {
            let running = SERVER_STATE
                .lock()
                .map_err(|_| "server state lock poisoned".to_string())?
                .take()
                .ok_or_else(|| "server disappeared during startup".to_string())?;
            let _ = cleanup_running_server(running);
            return Err(error);
        }

        Ok(status)
    }

    pub fn status() -> Result<Option<PluginServerStatus>, String> {
        let state = SERVER_STATE
            .lock()
            .map_err(|_| "server state lock poisoned".to_string())?;
        Ok(state.as_ref().map(|running| running.status.clone()))
    }

    pub fn stop() -> Result<Option<PluginServerStatus>, String> {
        if !EXECUTION_GATE.begin_command_stop()? {
            return Ok(None);
        }

        let running = match SERVER_STATE.lock() {
            Ok(mut state) => state.take(),
            Err(_) => {
                EXECUTION_GATE.restore_running();
                return Err("server state lock poisoned".to_string());
            }
        };
        let Some(running) = running else {
            let result = shutdown_dispatcher();
            EXECUTION_GATE.finish_stopped();
            return result.map(|()| None);
        };

        let result = cleanup_running_server(running);
        EXECUTION_GATE.finish_stopped();
        result.map(Some)
    }

    pub fn stop_for_unload() -> Result<Option<PluginServerStatus>, String> {
        if !EXECUTION_GATE.begin_unload_stop()? {
            return Ok(None);
        }

        let running = match SERVER_STATE.lock() {
            Ok(mut state) => state.take(),
            Err(_) => {
                EXECUTION_GATE.restore_running();
                return Err("server state lock poisoned".to_string());
            }
        };
        let Some(running) = running else {
            let result = shutdown_dispatcher();
            EXECUTION_GATE.finish_stopped();
            return result.map(|()| None);
        };

        let result = cleanup_running_server(running);
        EXECUTION_GATE.finish_stopped();
        result.map(Some)
    }

    pub(crate) fn begin_execution() -> Result<McpExecutionGuard<'static>, String> {
        EXECUTION_GATE.begin_execution()
    }

    pub(crate) fn apply_session_event(event: SessionEvent) -> Result<(), String> {
        let mut state = SERVER_STATE
            .lock()
            .map_err(|_| "server state lock poisoned".to_string())?;
        let Some(running) = state.as_mut() else {
            return Ok(());
        };

        let transition = reduce_session_event(
            &mut running.session_state,
            &mut running.session_generation,
            event,
        )?;
        let mut first_error = None;

        if transition.clear_target
            && let Err(error) = write_running_registry_target(running, None)
        {
            first_error = Some(error);
        }

        if let Some(generation) = transition.capture_generation {
            let request_result = running
                .snapshot_worker
                .as_ref()
                .ok_or_else(|| "snapshot worker is unavailable".to_string())
                .and_then(|worker| worker.request(generation));
            if let Err(error) = request_result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(crate) fn request_target_snapshot_refresh() -> Result<(), String> {
        let state = SERVER_STATE
            .lock()
            .map_err(|_| "server state lock poisoned".to_string())?;
        let Some(running) = state.as_ref() else {
            return Ok(());
        };
        if running.session_state != SessionState::Accessible {
            return Ok(());
        }

        running
            .snapshot_worker
            .as_ref()
            .ok_or_else(|| "snapshot worker is unavailable".to_string())?
            .request(running.session_generation)
    }
}

fn cleanup_running_server(mut running: RunningPluginServer) -> Result<PluginServerStatus, String> {
    let status = running.status.clone();
    let mut first_error = None;

    if let Some(mut worker) = running.snapshot_worker.take()
        && let Err(error) = worker.shutdown()
    {
        first_error = Some(error);
    }

    running.cancellation.cancel();
    if running.join_handle.join().is_err() && first_error.is_none() {
        first_error = Some("plugin server thread panicked".to_string());
    }

    if let Err(error) = shutdown_dispatcher()
        && first_error.is_none()
    {
        first_error = Some(error);
    }

    if let Some(registry) = running.registry {
        remove_instance_registry(registry);
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(status),
    }
}

fn shutdown_dispatcher() -> Result<(), String> {
    let dispatcher = DISPATCHER_STATE
        .lock()
        .map_err(|_| "dispatcher state lock poisoned".to_string())?
        .take();
    let Some(dispatcher) = dispatcher else {
        return Ok(());
    };
    dispatcher.shutdown().map_err(|error| error.to_string())
}

async fn run_server_loop(
    bind_addresses: Vec<String>,
    cancellation: CancellationToken,
    startup_tx: mpsc::Sender<Result<PluginServerStatus, String>>,
) -> Result<(), String> {
    let mut last_error = None;
    let mut listener = None;

    for bind_address in bind_addresses {
        match TcpListener::bind(&bind_address).await {
            Ok(bound_listener) => {
                listener = Some(bound_listener);
                break;
            }
            Err(error) => {
                last_error = Some(format!("{bind_address}: {error}"));
            }
        }
    }

    let listener = listener.ok_or_else(|| {
        format!(
            "failed to bind MCP server{}",
            last_error
                .as_deref()
                .map(|error| format!("; last error: {error}"))
                .unwrap_or_default()
        )
    })?;
    let local_addr = listener.local_addr().map_err(|error| error.to_string())?;
    let status = PluginServerStatus {
        mcp_url: format!("http://{}:{}/mcp", local_addr.ip(), local_addr.port()),
        registry_path: None,
    };
    startup_tx
        .send(Ok(status))
        .map_err(|_| "plugin server startup receiver dropped".to_string())?;

    let service: StreamableHttpService<WindbgMcpServer> = StreamableHttpService::new(
        || Ok(WindbgMcpServer::new()),
        Default::default(),
        StreamableHttpServerConfig {
            stateful_mode: true,
            sse_keep_alive: None,
            cancellation_token: cancellation.child_token(),
            ..Default::default()
        },
    );
    let router = Router::new().nest_service("/mcp", service);

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation.cancelled_owned().await })
        .await
        .map_err(|error| error.to_string())
}

fn bind_address_candidates(bind_address: Option<&str>) -> Vec<String> {
    if let Some(bind_address) = bind_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return vec![bind_address.to_string()];
    }

    (DEFAULT_BIND_PORT..DEFAULT_BIND_PORT + AUTO_BIND_PORT_COUNT)
        .map(|port| format!("{DEFAULT_BIND_HOST}:{port}"))
        .collect()
}

fn cleanup_stale_instance_registries() -> Result<(), String> {
    cleanup_stale_instance_registries_in(&instance_registry_directory())
}

fn cleanup_stale_instance_registries_in(directory: &Path) -> Result<(), String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let mut stems = BTreeSet::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some(stem) = instance_registry_stem(&name) {
            stems.insert(stem.to_string());
        }
    }

    for stem in stems {
        let lock_path = directory.join(format!("{stem}.lock"));
        let payload_path = directory.join(format!("{stem}.json"));
        let temp_path = registry_temp_path(&payload_path);
        match fs::remove_file(&lock_path) {
            Ok(()) => {
                let _ = fs::remove_file(payload_path);
                let _ = fs::remove_file(temp_path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::remove_file(&payload_path) {
                    Ok(()) => {
                        let _ = fs::remove_file(temp_path);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        let _ = fs::remove_file(temp_path);
                    }
                    Err(_) => {}
                }
            }
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.0 as i32) => {}
            Err(_) => {}
        }
    }

    Ok(())
}

fn instance_registry_stem(name: &str) -> Option<&str> {
    let stem = [".json.tmp", ".json", ".lock"]
        .into_iter()
        .find_map(|suffix| name.strip_suffix(suffix))?;
    let pid = stem.strip_prefix("instance-")?;
    (!pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit())).then_some(stem)
}

fn write_instance_registry(status: &PluginServerStatus) -> Result<InstanceRegistry, String> {
    let directory = instance_registry_directory();
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;

    let path = directory.join(format!("instance-{}.json", process::id()));
    let lock_path = path.with_extension("lock");
    let lock_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(&lock_path)
        .map_err(|error| error.to_string())?;
    let writer = InstanceRegistryWriter {
        path: path.clone(),
        base_payload: instance_registry_base_payload(status, host_arch(), current_unix_ms()?),
    };

    if let Err(error) = writer.write_target(None) {
        drop(lock_file);
        let _ = fs::remove_file(registry_temp_path(&path));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
        return Err(error);
    }

    Ok(InstanceRegistry {
        writer,
        lock_path,
        lock_file,
    })
}

fn remove_instance_registry(registry: InstanceRegistry) {
    let InstanceRegistry {
        writer,
        lock_path,
        lock_file,
    } = registry;
    let _ = fs::remove_file(&writer.path);
    let _ = fs::remove_file(registry_temp_path(&writer.path));
    drop(lock_file);
    let _ = fs::remove_file(lock_path);
}

fn instance_registry_directory() -> PathBuf {
    instance_registry_root_directory().join("instances")
}

fn instance_registry_root_directory() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
        .join("windbg-mcp-rs")
}

impl InstanceRegistryWriter {
    fn write_target(&self, current_target: Option<CurrentTargetSnapshot>) -> Result<(), String> {
        let payload = instance_registry_payload(&self.base_payload, current_target);
        write_registry_payload_atomically(&self.path, &payload)
    }
}

fn write_running_registry_target(
    running: &mut RunningPluginServer,
    current_target: Option<CurrentTargetSnapshot>,
) -> Result<(), String> {
    let Some(registry) = running.registry.as_ref() else {
        return Ok(());
    };
    registry.writer.write_target(current_target)
}

fn publish_target_snapshot(
    generation: u64,
    snapshot: &CurrentTargetSnapshot,
) -> Result<bool, String> {
    let mut state = SERVER_STATE
        .lock()
        .map_err(|_| "server state lock poisoned".to_string())?;
    let Some(running) = state.as_mut() else {
        return Ok(false);
    };
    if !snapshot_generation_can_publish(
        running.session_state,
        running.session_generation,
        generation,
    ) {
        return Ok(false);
    }

    write_running_registry_target(running, Some(snapshot.clone()))?;
    Ok(true)
}

fn snapshot_generation_can_publish(
    state: SessionState,
    current_generation: u64,
    requested_generation: u64,
) -> bool {
    state == SessionState::Accessible && current_generation == requested_generation
}

fn instance_registry_base_payload(
    status: &PluginServerStatus,
    host_arch: &str,
    started_unix_ms: u64,
) -> InstanceRegistryBasePayload {
    InstanceRegistryBasePayload {
        mcp_server_url: status.mcp_url.clone(),
        host_pid: process::id(),
        host_arch: host_arch.to_string(),
        host_process_path: env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
        started_unix_ms,
    }
}

fn instance_registry_payload(
    base: &InstanceRegistryBasePayload,
    current_target: Option<CurrentTargetSnapshot>,
) -> InstanceRegistryPayload {
    InstanceRegistryPayload {
        schema: 1,
        mcp_server_name: "windbg-mcp-rs",
        mcp_server_url: base.mcp_server_url.clone(),
        host_pid: base.host_pid,
        host_arch: base.host_arch.clone(),
        host_process_path: base.host_process_path.clone(),
        started_unix_ms: base.started_unix_ms,
        current_target,
    }
}

fn write_registry_payload_atomically(
    path: &Path,
    payload: &InstanceRegistryPayload,
) -> Result<(), String> {
    let temp_path = registry_temp_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
            .map_err(|error| error.to_string())?;
        serde_json::to_writer_pretty(&mut file, payload).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        file.flush().map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);

        let temp_wide = nul_terminated_wide_path(&temp_path);
        let path_wide = nul_terminated_wide_path(path);
        unsafe {
            MoveFileExW(
                PCWSTR(temp_wide.as_ptr()),
                PCWSTR(path_wide.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|error| error.to_string())
    })();

    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}

fn registry_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    PathBuf::from(temp)
}

fn nul_terminated_wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn current_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|error| error.to_string())
}

fn host_arch() -> &'static str {
    normalize_host_arch(std::env::consts::ARCH)
}

fn normalize_host_arch(target_arch: &str) -> &'static str {
    match target_arch {
        "x86" => "x86",
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => "unknown",
    }
}

pub(crate) fn notify_windbg(text: &str) -> Result<(), String> {
    let client = create_client_from_primary()?;
    unsafe {
        client
            .ConnectSession(
                DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE,
                0,
            )
            .map_err(|error| error.to_string())?;
    }

    let control = client
        .cast::<IDebugControl>()
        .map_err(|error| error.to_string())?;

    for line in text.lines() {
        let mut escaped = line.replace('%', "%%");
        escaped.push('\n');
        let c_text = CString::new(escaped).map_err(|_| "output text contained NUL".to_string())?;
        unsafe {
            control
                .OutputVaList(
                    DEBUG_OUTPUT_NORMAL,
                    PCSTR(c_text.as_ptr() as _),
                    std::ptr::null(),
                )
                .map_err(|error| error.to_string())?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn instance_registry_root_uses_application_directory() {
        let local_app_data = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);

        assert_eq!(
            instance_registry_root_directory(),
            local_app_data.join("windbg-mcp-rs")
        );
    }

    #[test]
    fn instance_registry_payload_uses_ordered_host_field_names() {
        let status = PluginServerStatus {
            mcp_url: "http://127.0.0.1:50051/mcp".to_string(),
            registry_path: None,
        };

        let base = instance_registry_base_payload(&status, "x64", 123);
        let payload = instance_registry_payload(&base, None);
        let payload_value = serde_json::to_value(&payload).expect("payload json value");

        assert_eq!(payload_value["schema"], 1);
        assert_eq!(payload_value["mcp_server_name"], "windbg-mcp-rs");
        assert_eq!(payload_value["mcp_server_url"], status.mcp_url);
        assert!(payload_value.get("host_pid").is_some());
        assert_eq!(payload_value["host_arch"], "x64");
        assert!(payload_value.get("host_process_path").is_some());
        assert!(payload_value.get("server").is_none());
        assert!(payload_value.get("mcp_url").is_none());
        assert!(payload_value.get("pid").is_none());
        assert!(payload_value.get("arch").is_none());
        assert!(payload_value.get("process_path").is_none());

        let payload_text = serde_json::to_string_pretty(&payload).expect("payload json text");
        let expected_order = [
            "\"schema\"",
            "\"mcp_server_name\"",
            "\"mcp_server_url\"",
            "\"host_pid\"",
            "\"host_arch\"",
            "\"host_process_path\"",
            "\"started_unix_ms\"",
            "\"current_target\"",
        ];
        let mut last_index = 0;
        for field in expected_order {
            let index = payload_text.find(field).expect("field present");
            assert!(index >= last_index, "{field} appeared out of order");
            last_index = index;
        }
    }

    fn test_registry_directory(name: &str) -> PathBuf {
        let directory = env::temp_dir().join(format!(
            "windbg-mcp-rs-{name}-{}-{}",
            process::id(),
            current_unix_ms().expect("test timestamp")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create test registry directory");
        directory
    }

    #[test]
    fn atomic_registry_replace_failure_preserves_old_payload() {
        let directory = test_registry_directory("atomic-replace");
        let path = directory.join("instance-1.json");
        let status = PluginServerStatus {
            mcp_url: "http://127.0.0.1:50051/mcp".to_string(),
            registry_path: None,
        };
        let base = instance_registry_base_payload(&status, "x64", 123);
        let old_payload = instance_registry_payload(&base, None);
        write_registry_payload_atomically(&path, &old_payload).expect("initial registry write");
        let destination_handle = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .expect("hold destination without delete sharing");

        let new_payload = instance_registry_payload(&base, Some(test_snapshot(456)));
        assert!(
            write_registry_payload_atomically(&path, &new_payload).is_err(),
            "replace must fail while destination denies delete sharing"
        );
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read preserved registry payload"))
                .expect("preserved payload remains valid JSON");
        assert!(persisted["current_target"].is_null());
        assert!(!registry_temp_path(&path).exists());

        drop(destination_handle);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn stale_cleanup_respects_active_lock_then_removes_complete_stem() {
        let directory = test_registry_directory("stale-cleanup");
        let payload_path = directory.join("instance-42.json");
        let temp_path = registry_temp_path(&payload_path);
        let lock_path = payload_path.with_extension("lock");
        fs::write(&payload_path, b"{}\n").expect("write payload marker");
        fs::write(&temp_path, b"partial").expect("write temp marker");
        let lock_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ)
            .open(&lock_path)
            .expect("create active lock");

        cleanup_stale_instance_registries_in(&directory).expect("active cleanup");
        assert!(lock_path.exists());
        assert!(payload_path.exists());
        assert!(temp_path.exists());

        drop(lock_file);
        cleanup_stale_instance_registries_in(&directory).expect("stale cleanup");
        assert!(!lock_path.exists());
        assert!(!payload_path.exists());
        assert!(!temp_path.exists());

        let _ = fs::remove_dir_all(directory);
    }
    #[test]
    fn normalizes_supported_host_architectures() {
        assert_eq!(normalize_host_arch("x86"), "x86");
        assert_eq!(normalize_host_arch("x86_64"), "x64");
        assert_eq!(normalize_host_arch("aarch64"), "arm64");
        assert_eq!(normalize_host_arch("mips64"), "unknown");
    }
    fn test_snapshot(updated_unix_ms: u64) -> CurrentTargetSnapshot {
        CurrentTargetSnapshot {
            kind: "user".to_string(),
            name: Some("target.exe".to_string()),
            source_path: None,
            transport: None,
            endpoint: None,
            updated_unix_ms,
        }
    }

    fn wait_until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !predicate() {
            assert!(
                Instant::now() < deadline,
                "condition did not become true before timeout"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn session_reducer_enforces_generation_and_target_rules() {
        let mut state = SessionState::Inactive;
        let mut generation = 0;
        let mut current_target = Some(test_snapshot(1));

        let transition = reduce_session_event(&mut state, &mut generation, SessionEvent::Active)
            .expect("active transition");
        if transition.clear_target {
            current_target = None;
        }
        assert_eq!(state, SessionState::Inaccessible);
        assert_eq!(generation, 1);
        assert!(current_target.is_none());

        let transition =
            reduce_session_event(&mut state, &mut generation, SessionEvent::Accessible)
                .expect("accessible transition");
        assert_eq!(state, SessionState::Accessible);
        assert_eq!(generation, 2);
        assert_eq!(transition.capture_generation, Some(2));
        assert!(!snapshot_generation_can_publish(state, generation, 1));
        assert!(snapshot_generation_can_publish(state, generation, 2));
        current_target = Some(test_snapshot(2));

        let transition =
            reduce_session_event(&mut state, &mut generation, SessionEvent::Accessible)
                .expect("duplicate accessible transition");
        assert_eq!(state, SessionState::Accessible);
        assert_eq!(generation, 2);
        assert_eq!(transition.capture_generation, Some(2));

        let transition = reduce_session_event(&mut state, &mut generation, SessionEvent::Active)
            .expect("late active transition");
        assert_eq!(state, SessionState::Accessible);
        assert_eq!(generation, 2);
        assert!(!transition.clear_target);

        let transition =
            reduce_session_event(&mut state, &mut generation, SessionEvent::Inaccessible)
                .expect("inaccessible transition");
        assert_eq!(state, SessionState::Inaccessible);
        assert_eq!(generation, 3);
        assert!(!transition.clear_target);
        assert!(!snapshot_generation_can_publish(state, generation, 3));
        assert_eq!(
            current_target.as_ref().map(|target| target.updated_unix_ms),
            Some(2)
        );

        let transition =
            reduce_session_event(&mut state, &mut generation, SessionEvent::Accessible)
                .expect("second accessible transition");
        assert_eq!(state, SessionState::Accessible);
        assert_eq!(generation, 4);
        assert_eq!(transition.capture_generation, Some(4));
        assert!(!snapshot_generation_can_publish(state, generation, 2));
        assert!(snapshot_generation_can_publish(state, generation, 4));

        let transition = reduce_session_event(&mut state, &mut generation, SessionEvent::Inactive)
            .expect("inactive transition");
        if transition.clear_target {
            current_target = None;
        }
        assert_eq!(state, SessionState::Inactive);
        assert_eq!(generation, 5);
        assert!(current_target.is_none());

        let transition = reduce_session_event(&mut state, &mut generation, SessionEvent::Inactive)
            .expect("duplicate inactive transition");
        assert_eq!(generation, 5);
        assert_eq!(transition, SessionTransition::default());
    }

    #[test]
    fn session_reducer_rejects_generation_overflow_without_mutation() {
        let mut state = SessionState::Inactive;
        let mut generation = u64::MAX;

        let error = reduce_session_event(&mut state, &mut generation, SessionEvent::Active)
            .expect_err("overflow must fail");

        assert_eq!(error, "session generation overflow");
        assert_eq!(state, SessionState::Inactive);
        assert_eq!(generation, u64::MAX);
    }

    #[test]
    fn snapshot_worker_coalesces_pending_requests_to_latest_generation() {
        let published = Arc::new(Mutex::new(Vec::new()));
        let published_for_worker = Arc::clone(&published);
        let mut worker = SnapshotWorker::spawn(
            || Some(test_snapshot(1)),
            move |generation, _| {
                published_for_worker
                    .lock()
                    .expect("published lock")
                    .push(generation);
                Ok(true)
            },
            SnapshotTiming {
                initial_delay: Duration::from_millis(50),
                retry_delay: Duration::ZERO,
                max_attempts: 1,
            },
        )
        .expect("worker should start");

        worker.request(1).expect("first request");
        worker.request(2).expect("second request");
        worker.request(3).expect("third request");
        wait_until(|| !published.lock().expect("published lock").is_empty());
        worker.shutdown().expect("worker should stop");

        assert_eq!(*published.lock().expect("published lock"), vec![3]);
    }

    #[test]
    fn snapshot_worker_repeats_request_received_during_capture() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let capture_count = Arc::new(AtomicUsize::new(0));
        let publish_count = Arc::new(AtomicUsize::new(0));
        let capture_count_for_worker = Arc::clone(&capture_count);
        let publish_count_for_worker = Arc::clone(&publish_count);
        let (capture_started_tx, capture_started_rx) = mpsc::channel();
        let (release_capture_tx, release_capture_rx) = mpsc::channel();
        let mut worker = SnapshotWorker::spawn(
            move || {
                let invocation = capture_count_for_worker.fetch_add(1, Ordering::SeqCst);
                if invocation == 0 {
                    capture_started_tx.send(()).expect("signal capture");
                    release_capture_rx.recv().expect("release capture");
                }
                Some(test_snapshot(invocation as u64))
            },
            move |_, _| {
                publish_count_for_worker.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            },
            SnapshotTiming {
                initial_delay: Duration::ZERO,
                retry_delay: Duration::ZERO,
                max_attempts: 1,
            },
        )
        .expect("worker should start");

        worker.request(7).expect("initial request");
        capture_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("capture should start");
        worker.request(7).expect("request during capture");
        release_capture_tx.send(()).expect("release first capture");
        wait_until(|| capture_count.load(Ordering::SeqCst) >= 2);
        wait_until(|| publish_count.load(Ordering::SeqCst) >= 2);
        worker.shutdown().expect("worker should stop");

        let captures_after_join = capture_count.load(Ordering::SeqCst);
        let publishes_after_join = publish_count.load(Ordering::SeqCst);
        assert!(worker.request(7).is_err());
        thread::sleep(Duration::from_millis(20));
        assert_eq!(capture_count.load(Ordering::SeqCst), captures_after_join);
        assert_eq!(publish_count.load(Ordering::SeqCst), publishes_after_join);
    }

    #[test]
    fn snapshot_worker_shutdown_interrupts_long_initial_and_retry_delays() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut initial_delay_worker = SnapshotWorker::spawn(
            || Some(test_snapshot(1)),
            |_, _| Ok(true),
            SnapshotTiming {
                initial_delay: Duration::from_secs(60 * 60),
                retry_delay: Duration::from_secs(60 * 60),
                max_attempts: 6,
            },
        )
        .expect("initial delay worker should start");
        initial_delay_worker.request(1).expect("initial request");
        let started = Instant::now();
        initial_delay_worker
            .shutdown()
            .expect("initial delay worker should stop");
        assert!(started.elapsed() < Duration::from_secs(1));

        let capture_count = Arc::new(AtomicUsize::new(0));
        let capture_count_for_worker = Arc::clone(&capture_count);
        let mut retry_delay_worker = SnapshotWorker::spawn(
            move || {
                capture_count_for_worker.fetch_add(1, Ordering::SeqCst);
                None
            },
            |_, _| Ok(true),
            SnapshotTiming {
                initial_delay: Duration::ZERO,
                retry_delay: Duration::from_secs(60 * 60),
                max_attempts: 6,
            },
        )
        .expect("retry delay worker should start");
        retry_delay_worker.request(1).expect("retry request");
        wait_until(|| capture_count.load(Ordering::SeqCst) == 1);
        let started = Instant::now();
        retry_delay_worker
            .shutdown()
            .expect("retry delay worker should stop");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(capture_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn plugin_server_bind_failure_leaves_no_running_instance() {
        let error = PluginServerControl::start(Some("not-a-socket-address"))
            .expect_err("invalid bind address must fail");

        assert!(error.contains("failed to bind MCP server"));
        assert!(
            PluginServerControl::status()
                .expect("status lock")
                .is_none()
        );
    }

    #[test]
    fn execution_gate_rejects_command_stop_while_execution_is_active() {
        let gate = McpExecutionGate::new();
        gate.mark_running().expect("gate should run");
        let guard = gate.begin_execution().expect("execution should start");

        let started = Instant::now();
        let error = gate
            .begin_command_stop()
            .expect_err("command stop must fail while active");

        assert_eq!(error, STOP_DURING_COMMAND_ERROR);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(gate.phase(), McpExecutionPhase::Running);
        drop(guard);

        assert!(gate.begin_command_stop().expect("command stop transition"));
        let cleanup_result: Result<(), String> = Err("simulated cleanup failure".to_string());
        gate.finish_stopped();
        assert!(cleanup_result.is_err());
        assert_eq!(gate.phase(), McpExecutionPhase::Stopped);
    }

    #[test]
    fn execution_gate_unload_waits_and_rejects_new_execution() {
        let gate = Arc::new(McpExecutionGate::new());
        gate.mark_running().expect("gate should run");
        let guard = gate.begin_execution().expect("execution should start");
        let gate_for_unload = Arc::clone(&gate);
        let (unload_complete_tx, unload_complete_rx) = mpsc::channel();

        let unload_thread = thread::spawn(move || {
            let should_cleanup = gate_for_unload
                .begin_unload_stop()
                .expect("unload transition");
            unload_complete_tx
                .send(should_cleanup)
                .expect("signal unload completion");
            gate_for_unload.finish_stopped();
        });

        wait_until(|| gate.phase() == McpExecutionPhase::Stopping);
        let execution_error = match gate.begin_execution() {
            Ok(_) => panic!("stopping gate must reject execution"),
            Err(error) => error,
        };
        assert_eq!(execution_error, EXECUTION_UNAVAILABLE_ERROR);
        assert!(
            unload_complete_rx
                .recv_timeout(Duration::from_millis(20))
                .is_err(),
            "unload must remain blocked while the guard is active"
        );

        drop(guard);
        assert!(
            unload_complete_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("unload should continue")
        );
        unload_thread.join().expect("unload thread should join");
        assert_eq!(gate.phase(), McpExecutionPhase::Stopped);
    }
}

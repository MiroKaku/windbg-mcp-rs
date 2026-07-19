use std::sync::{LazyLock, Mutex};

use windows::{
    Win32::System::Diagnostics::Debug::{
        EXCEPTION_RECORD64,
        Extensions::{
            DEBUG_CES_CURRENT_THREAD, DEBUG_CES_EXECUTION_STATUS, DEBUG_CES_SYSTEMS,
            DEBUG_CONNECT_SESSION_NO_ANNOUNCE, DEBUG_CONNECT_SESSION_NO_VERSION,
            DEBUG_EVENT_CHANGE_ENGINE_STATE, DEBUG_EVENT_CREATE_PROCESS, DEBUG_EVENT_EXIT_PROCESS,
            DEBUG_EVENT_SESSION_STATUS, DEBUG_SESSION_ACTIVE, DEBUG_SESSION_END,
            DEBUG_SESSION_END_SESSION_ACTIVE_DETACH, DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE,
            DEBUG_SESSION_END_SESSION_PASSIVE, DEBUG_SESSION_FAILURE, DEBUG_SESSION_HIBERNATE,
            DEBUG_SESSION_REBOOT, DEBUG_STATUS_BREAK, DEBUG_STATUS_MASK, IDebugBreakpoint,
            IDebugClient, IDebugEventCallbacks, IDebugEventCallbacks_Impl,
        },
    },
    core::{PCSTR, Ref, Result as WinResult, implement},
};

use crate::{
    plugin_server::{PluginServerControl, SessionEvent},
    primary_client::create_client_from_primary,
};

struct EventClient {
    inner: IDebugClient,
}

struct EventCallbacks {
    _inner: IDebugEventCallbacks,
}

// SAFETY: The callback registration is held only to keep DbgEng COM interfaces
// alive. Calls into dbgeng are performed through DbgEng's callback dispatch and
// the existing command dispatcher path, not by sharing mutable Rust state.
unsafe impl Send for EventClient {}
unsafe impl Send for EventCallbacks {}

struct EventCallbackRegistration {
    client: EventClient,
    _callbacks: EventCallbacks,
}

static EVENT_CALLBACKS: LazyLock<Mutex<Option<EventCallbackRegistration>>> =
    LazyLock::new(|| Mutex::new(None));

#[implement(IDebugEventCallbacks)]
struct TargetEventCallbacks;

impl IDebugEventCallbacks_Impl for TargetEventCallbacks_Impl {
    fn GetInterestMask(&self) -> WinResult<u32> {
        Ok(DEBUG_EVENT_CREATE_PROCESS
            | DEBUG_EVENT_EXIT_PROCESS
            | DEBUG_EVENT_CHANGE_ENGINE_STATE
            | DEBUG_EVENT_SESSION_STATUS)
    }

    fn Breakpoint(&self, _bp: Ref<'_, IDebugBreakpoint>) -> WinResult<()> {
        Ok(())
    }

    fn Exception(&self, _exception: *const EXCEPTION_RECORD64, _firstchance: u32) -> WinResult<()> {
        Ok(())
    }

    fn CreateThread(&self, _handle: u64, _dataoffset: u64, _startoffset: u64) -> WinResult<()> {
        Ok(())
    }

    fn ExitThread(&self, _exitcode: u32) -> WinResult<()> {
        Ok(())
    }

    fn CreateProcessA(
        &self,
        _imagefilehandle: u64,
        _handle: u64,
        _baseoffset: u64,
        _modulesize: u32,
        _modulename: &PCSTR,
        _imagename: &PCSTR,
        _checksum: u32,
        _timedatestamp: u32,
        _initialthreadhandle: u64,
        _threaddataoffset: u64,
        _startoffset: u64,
    ) -> WinResult<()> {
        let _ = PluginServerControl::request_target_snapshot_refresh();
        Ok(())
    }

    fn ExitProcess(&self, _exitcode: u32) -> WinResult<()> {
        let _ = PluginServerControl::request_target_snapshot_refresh();
        Ok(())
    }

    fn LoadModule(
        &self,
        _imagefilehandle: u64,
        _baseoffset: u64,
        _modulesize: u32,
        _modulename: &PCSTR,
        _imagename: &PCSTR,
        _checksum: u32,
        _timedatestamp: u32,
    ) -> WinResult<()> {
        Ok(())
    }

    fn UnloadModule(&self, _imagebasename: &PCSTR, _baseoffset: u64) -> WinResult<()> {
        Ok(())
    }

    fn SystemError(&self, _error: u32, _level: u32) -> WinResult<()> {
        Ok(())
    }

    fn SessionStatus(&self, status: u32) -> WinResult<()> {
        if let Some(event) = session_event_for_status(status) {
            let _ = PluginServerControl::apply_session_event(event);
        }
        Ok(())
    }

    fn ChangeDebuggeeState(&self, _flags: u32, _argument: u64) -> WinResult<()> {
        Ok(())
    }

    fn ChangeEngineState(&self, flags: u32, argument: u64) -> WinResult<()> {
        if engine_state_requests_refresh(flags, argument) {
            let _ = PluginServerControl::request_target_snapshot_refresh();
        }
        Ok(())
    }

    fn ChangeSymbolState(&self, _flags: u32, _argument: u64) -> WinResult<()> {
        Ok(())
    }
}

pub(crate) fn ensure_target_event_callbacks() -> Result<(), String> {
    let mut state = EVENT_CALLBACKS
        .lock()
        .map_err(|_| "event callback state lock poisoned".to_string())?;
    if state.is_some() {
        return Ok(());
    }

    let client = create_client_from_primary()?;
    unsafe {
        client
            .ConnectSession(
                DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE,
                0,
            )
            .map_err(|error| error.to_string())?;
    }

    let callbacks: IDebugEventCallbacks = TargetEventCallbacks.into();
    unsafe {
        client
            .SetEventCallbacks(&callbacks)
            .map_err(|error| error.to_string())?;
    }

    *state = Some(EventCallbackRegistration {
        client: EventClient { inner: client },
        _callbacks: EventCallbacks { _inner: callbacks },
    });
    Ok(())
}

pub(crate) fn clear_target_event_callbacks() -> Result<(), String> {
    let registration = {
        let mut state = EVENT_CALLBACKS
            .lock()
            .map_err(|_| "event callback state lock poisoned".to_string())?;
        state.take()
    };
    let Some(registration) = registration else {
        return Ok(());
    };

    let result = unsafe {
        registration
            .client
            .inner
            .SetEventCallbacks(None::<&IDebugEventCallbacks>)
            .map_err(|error| error.to_string())
    };
    drop(registration);
    result
}

fn session_event_for_status(status: u32) -> Option<SessionEvent> {
    match status {
        DEBUG_SESSION_ACTIVE => Some(SessionEvent::Active),
        DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE
        | DEBUG_SESSION_END_SESSION_ACTIVE_DETACH
        | DEBUG_SESSION_END_SESSION_PASSIVE
        | DEBUG_SESSION_END
        | DEBUG_SESSION_REBOOT
        | DEBUG_SESSION_HIBERNATE
        | DEBUG_SESSION_FAILURE => Some(SessionEvent::Inactive),
        _ => None,
    }
}

fn engine_state_requests_refresh(flags: u32, argument: u64) -> bool {
    flags & (DEBUG_CES_CURRENT_THREAD | DEBUG_CES_SYSTEMS) != 0
        || flags == DEBUG_CES_EXECUTION_STATUS
            && (argument as u32) & DEBUG_STATUS_MASK == DEBUG_STATUS_BREAK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_documented_session_statuses_to_lifecycle_events() {
        assert_eq!(
            session_event_for_status(DEBUG_SESSION_ACTIVE),
            Some(SessionEvent::Active)
        );
        for status in [
            DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE,
            DEBUG_SESSION_END_SESSION_ACTIVE_DETACH,
            DEBUG_SESSION_END_SESSION_PASSIVE,
            DEBUG_SESSION_END,
            DEBUG_SESSION_REBOOT,
            DEBUG_SESSION_HIBERNATE,
            DEBUG_SESSION_FAILURE,
        ] {
            assert_eq!(
                session_event_for_status(status),
                Some(SessionEvent::Inactive)
            );
        }
        assert_eq!(session_event_for_status(u32::MAX), None);
    }

    #[test]
    fn maps_engine_state_flags_without_reading_undefined_arguments() {
        assert!(engine_state_requests_refresh(DEBUG_CES_CURRENT_THREAD, 0));
        assert!(engine_state_requests_refresh(DEBUG_CES_SYSTEMS, 0));
        assert!(engine_state_requests_refresh(
            DEBUG_CES_EXECUTION_STATUS,
            u64::from(DEBUG_STATUS_BREAK)
        ));
        assert!(!engine_state_requests_refresh(
            DEBUG_CES_EXECUTION_STATUS,
            0
        ));
        assert!(!engine_state_requests_refresh(
            DEBUG_CES_EXECUTION_STATUS | 0x8000_0000,
            u64::from(DEBUG_STATUS_BREAK)
        ));
    }
}

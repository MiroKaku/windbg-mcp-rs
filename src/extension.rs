use std::ffi::CString;

use windows::{
    Win32::{
        Foundation::{E_FAIL, E_POINTER, S_OK},
        System::Diagnostics::Debug::Extensions::{
            DEBUG_NOTIFY_SESSION_ACCESSIBLE, DEBUG_NOTIFY_SESSION_ACTIVE,
            DEBUG_NOTIFY_SESSION_INACCESSIBLE, DEBUG_NOTIFY_SESSION_INACTIVE, DEBUG_OUTPUT_ERROR,
            DEBUG_OUTPUT_NORMAL, IDebugClient, IDebugControl,
        },
    },
    core::{HRESULT, Interface, PCSTR, Ref, Result as WinResult},
};

use crate::plugin_server::{PluginServerStatus, SessionEvent, notify_windbg};
use crate::{
    Catalog,
    plugin_server::PluginServerControl,
    primary_client::{clear_primary_client, initialize_primary_client},
    target_events::{clear_target_event_callbacks, ensure_target_event_callbacks},
};

const EXTENSION_MAJOR: u32 = 0;
const EXTENSION_MINOR: u32 = 1;

/// # Safety
/// Called by dbgeng with valid, non-null pointers to `version` and `flags`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DebugExtensionInitialize(
    version: *mut u32,
    flags: *mut u32,
) -> HRESULT {
    if version.is_null() || flags.is_null() {
        return E_POINTER;
    }

    unsafe {
        *version = (EXTENSION_MAJOR << 16) | EXTENSION_MINOR;
        *flags = 0;
    }

    if let Err(error) = initialize_primary_client() {
        let _ = notify_windbg(&format!(
            "Failed to initialize WinDbg MCP primary client: {error}\n"
        ));
    }

    S_OK
}

/// # Safety
/// Called by dbgeng during extension unload. No parameters are passed.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DebugExtensionUninitialize() {
    if let Err(error) = clear_target_event_callbacks() {
        let _ = notify_windbg(&format!(
            "WinDbg MCP event callback unregistration failed: {error}\n"
        ));
    }
    if let Err(error) = PluginServerControl::stop_for_unload() {
        let _ = notify_windbg(&format!(
            "WinDbg MCP server unload cleanup failed: {error}\n"
        ));
    }
    clear_primary_client();
}

/// # Safety
/// Called by dbgeng with a session notification code. `_argument` is unused and
/// ignored as documented by the extension callback contract.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DebugExtensionNotify(notify: u32, _argument: u64) {
    match notify {
        DEBUG_NOTIFY_SESSION_ACTIVE => match PluginServerControl::start(None) {
            Ok(status) => {
                if let Err(error) = ensure_target_event_callbacks() {
                    let _ = notify_windbg(&format!(
                        "WinDbg MCP event callback registration failed: {error}\n"
                    ));
                }
                if let Err(error) = PluginServerControl::apply_session_event(SessionEvent::Active) {
                    let _ = notify_windbg(&format!(
                        "WinDbg MCP active session transition failed: {error}\n"
                    ));
                }
                let _ = notify_windbg(&format_status(&status));
            }
            Err(error) => {
                let _ = notify_windbg(&format!("WinDbg MCP server auto-start failed: {error}\n"));
            }
        },
        DEBUG_NOTIFY_SESSION_ACCESSIBLE => {
            if let Err(error) = PluginServerControl::start(None) {
                let _ = notify_windbg(&format!(
                    "WinDbg MCP server auto-start failed on accessible session: {error}\n"
                ));
                return;
            }
            if let Err(error) = ensure_target_event_callbacks() {
                let _ = notify_windbg(&format!(
                    "WinDbg MCP event callback registration failed on accessible session: {error}\n"
                ));
            }
            if let Err(error) = PluginServerControl::apply_session_event(SessionEvent::Accessible) {
                let _ = notify_windbg(&format!(
                    "WinDbg MCP accessible session transition failed: {error}\n"
                ));
            }
        }
        DEBUG_NOTIFY_SESSION_INACCESSIBLE => {
            if let Err(error) = PluginServerControl::apply_session_event(SessionEvent::Inaccessible)
            {
                let _ = notify_windbg(&format!(
                    "WinDbg MCP inaccessible session transition failed: {error}\n"
                ));
            }
        }
        DEBUG_NOTIFY_SESSION_INACTIVE => {
            if let Err(error) = PluginServerControl::apply_session_event(SessionEvent::Inactive) {
                let _ = notify_windbg(&format!(
                    "WinDbg MCP inactive session transition failed: {error}\n"
                ));
            }
        }
        _ => {}
    }
}

/// # Safety
/// Called by dbgeng with a valid `IDebugClient` reference and an optional
/// null-terminated command string.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn mcp(client: Ref<IDebugClient>, args: PCSTR) -> HRESULT {
    match run_mcp_command(client, args) {
        Ok(()) => S_OK,
        Err(error) => error.code(),
    }
}

fn run_mcp_command(client: Ref<IDebugClient>, args: PCSTR) -> WinResult<()> {
    let client = client
        .cloned()
        .ok_or_else(|| windows::core::Error::from(E_POINTER))?;
    let control = client.cast::<IDebugControl>()?;
    let raw_args = if args.is_null() {
        String::new()
    } else {
        unsafe { args.to_string() }.unwrap_or_default()
    };
    let trimmed = raw_args.trim();

    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("help") {
        return write_text(&control, help_text(), DEBUG_OUTPUT_NORMAL);
    }

    if let Some(rest) = trimmed.strip_prefix("doc ") {
        return command_doc(&control, rest.trim());
    }

    if let Some(rest) = trimmed.strip_prefix("catalog") {
        return command_catalog(&control, rest.trim());
    }

    if let Some(rest) = trimmed.strip_prefix("serve") {
        return command_serve(&control, rest.trim());
    }

    if trimmed.eq_ignore_ascii_case("status") {
        return command_status(&control);
    }

    if trimmed.eq_ignore_ascii_case("stop") {
        return command_stop(&control);
    }

    write_text(
        &control,
        &format!(
            "Unknown !mcp subcommand `{trimmed}`. Run `!mcp help` to list supported commands.\n"
        ),
        DEBUG_OUTPUT_ERROR,
    )
}

fn help_text() -> &'static str {
    "windbg-mcp commands:\n\n  !mcp help\n      Show this help text.\n\n  !mcp serve [host:port]\n      Start the MCP Streamable HTTP server inside the WinDbg plugin. Default bind tries 127.0.0.1:50051 through 127.0.0.1:50070, endpoint: /mcp\n\n  !mcp status\n      Show whether the in-process MCP server is running.\n\n  !mcp stop\n      Stop the in-process MCP server.\n\n  !mcp catalog [query]\n      List catalog entries or search the extracted debugger command catalog.\n\n  !mcp doc <token-or-id>\n      Show the static documentation for one extracted command topic."
}

fn command_serve(control: &IDebugControl, bind: &str) -> WinResult<()> {
    match PluginServerControl::start((!bind.is_empty()).then_some(bind)) {
        Ok(status) => write_text(control, &format_status(&status), DEBUG_OUTPUT_NORMAL),
        Err(error) => write_text(
            control,
            &format!("Failed to start WinDbg MCP server: {error}\n"),
            DEBUG_OUTPUT_ERROR,
        ),
    }
}

fn command_status(control: &IDebugControl) -> WinResult<()> {
    match PluginServerControl::status() {
        Ok(Some(status)) => write_text(control, &format_status(&status), DEBUG_OUTPUT_NORMAL),
        Ok(None) => write_text(
            control,
            "WinDbg MCP server is not running.\n",
            DEBUG_OUTPUT_NORMAL,
        ),
        Err(error) => Err(windows::core::Error::new(E_FAIL, error)),
    }
}

fn format_status(status: &PluginServerStatus) -> String {
    let mut text = format!("WinDbg MCP server is running at {}\n", status.mcp_url);
    if let Some(path) = &status.registry_path {
        text.push_str(&format!("Instance registry: {}\n", path.display()));
    }
    text
}

fn command_stop(control: &IDebugControl) -> WinResult<()> {
    match PluginServerControl::stop() {
        Ok(Some(status)) => write_text(
            control,
            &format!("Stopped WinDbg MCP server at {}\n", status.mcp_url),
            DEBUG_OUTPUT_NORMAL,
        ),
        Ok(None) => write_text(
            control,
            "WinDbg MCP server was not running.\n",
            DEBUG_OUTPUT_NORMAL,
        ),
        Err(error) => Err(windows::core::Error::new(E_FAIL, error)),
    }
}

fn command_doc(control: &IDebugControl, query: &str) -> WinResult<()> {
    let catalog = Catalog::global();
    let entry = catalog
        .lookup(query)
        .or_else(|| catalog.search(query, None, 1).into_iter().next());

    match entry {
        Some(entry) => {
            let mut text = String::new();
            text.push_str(&format!("{}\n\n", entry.title));
            text.push_str(&format!("tokens: {}\n", entry.tokens.join(", ")));
            text.push_str(&format!("id: {}\n\n", entry.id));
            text.push_str(&entry.documentation);
            write_text(control, &text, DEBUG_OUTPUT_NORMAL)
        }
        None => write_text(
            control,
            &format!("No catalog entry matched `{query}`.\n"),
            DEBUG_OUTPUT_ERROR,
        ),
    }
}

fn command_catalog(control: &IDebugControl, query: &str) -> WinResult<()> {
    let catalog = Catalog::global();
    let results = if query.is_empty() {
        catalog.search("", None, 25)
    } else {
        catalog.search(query, None, 25)
    };

    let mut text = String::new();
    if query.is_empty() {
        text.push_str("First 25 extracted debugger command topics:\n\n");
    } else {
        text.push_str(&format!("Catalog matches for `{query}`:\n\n"));
    }

    for entry in results {
        text.push_str(&format!(
            "- {} | id={} | tokens={}\n  {}\n\n",
            entry.title,
            entry.id,
            entry.tokens.join(", "),
            entry.summary
        ));
    }

    write_text(control, &text, DEBUG_OUTPUT_NORMAL)
}

fn write_text(control: &IDebugControl, text: &str, mask: u32) -> WinResult<()> {
    if text.is_empty() {
        return Ok(());
    }

    for line in text.lines() {
        let mut escaped = line.replace('%', "%%");
        escaped.push('\n');
        let c_text = CString::new(escaped).map_err(|_| windows::core::Error::from(E_POINTER))?;
        unsafe {
            control.OutputVaList(mask, PCSTR(c_text.as_ptr() as _), std::ptr::null())?;
        }
    }
    Ok(())
}

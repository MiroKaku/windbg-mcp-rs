use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use windows::{
    Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_ANY_ID, DEBUG_CLASS_IMAGE_FILE, DEBUG_CLASS_KERNEL, DEBUG_CLASS_USER_WINDOWS,
        DEBUG_CONNECT_SESSION_NO_ANNOUNCE, DEBUG_CONNECT_SESSION_NO_VERSION, DEBUG_DUMP_FILE_BASE,
        DEBUG_MODNAME_IMAGE, DEBUG_USER_WINDOWS_DUMP, DEBUG_USER_WINDOWS_DUMP_WINDOWS_CE,
        DEBUG_USER_WINDOWS_SMALL_DUMP, IDebugClient4, IDebugControl, IDebugSymbols3,
        IDebugSystemObjects, IDebugSystemObjects4,
    },
    core::Interface,
};

use crate::primary_client::create_client_from_primary;

const DBGENG_PATH_BUFFER_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CurrentTargetSnapshot {
    pub(crate) kind: String,
    pub(crate) name: Option<String>,
    pub(crate) source_path: Option<String>,
    pub(crate) transport: Option<String>,
    pub(crate) endpoint: Option<String>,
    pub(crate) updated_unix_ms: u64,
}

#[derive(Debug)]
struct DbgEngApiTargetInfo {
    debuggee_class: Option<u32>,
    debuggee_qualifier: Option<u32>,
    system_server_name: Option<String>,
    process_exe: Option<String>,
    process_exe_wide: Option<String>,
    module_image: Option<String>,
    dump_file_path: Option<String>,
}

pub(crate) fn capture_current_target_snapshot() -> Option<CurrentTargetSnapshot> {
    let updated_unix_ms = current_unix_ms().unwrap_or_default();
    capture_dbgeng_api_target_info()
        .ok()
        .and_then(|info| build_current_target_snapshot(info, updated_unix_ms))
}

fn build_current_target_snapshot(
    info: DbgEngApiTargetInfo,
    updated_unix_ms: u64,
) -> Option<CurrentTargetSnapshot> {
    let process_name = choose_better_target_path(
        info.process_exe_wide.as_deref(),
        info.process_exe.as_deref(),
    );
    let name = choose_better_target_path(process_name.as_deref(), info.module_image.as_deref());
    let source_path = info.dump_file_path;
    let kind = infer_target_kind(
        info.debuggee_class,
        info.debuggee_qualifier,
        source_path.as_deref().or(name.as_deref()),
    )
    .to_string();
    let (transport, endpoint) = info
        .system_server_name
        .as_deref()
        .map(parse_debug_transport)
        .unwrap_or((None, None));

    if name.is_none()
        && source_path.is_none()
        && info.system_server_name.is_none()
        && info.debuggee_class.is_none()
        && info.debuggee_qualifier.is_none()
    {
        return None;
    }

    Some(CurrentTargetSnapshot {
        kind,
        name,
        source_path,
        transport,
        endpoint,
        updated_unix_ms,
    })
}

fn capture_dbgeng_api_target_info() -> Result<DbgEngApiTargetInfo, String> {
    let client = create_client_from_primary()?;
    unsafe {
        client
            .ConnectSession(
                DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE,
                0,
            )
            .map_err(|error| error.to_string())?;
    }

    let (debuggee_class, debuggee_qualifier) = match client.cast::<IDebugControl>() {
        Ok(control) => unsafe {
            let mut class = 0u32;
            let mut qualifier = 0u32;
            match control.GetDebuggeeType(&mut class, &mut qualifier) {
                Ok(()) => (Some(class), Some(qualifier)),
                Err(_) => (None, None),
            }
        },
        Err(_) => (None, None),
    };

    let objects = client.cast::<IDebugSystemObjects>();
    let objects4 = client.cast::<IDebugSystemObjects4>();

    let system_server_name = objects4.as_ref().ok().and_then(|objects| unsafe {
        dbgeng_wide_string(|buffer, actual_size| {
            objects.GetCurrentSystemServerNameWide(buffer, actual_size)
        })
        .map(clean_dbgeng_path)
        .ok()
        .flatten()
    });

    let process_exe_wide = objects4.as_ref().ok().and_then(|objects| unsafe {
        dbgeng_wide_string(|buffer, actual_size| {
            objects.GetCurrentProcessExecutableNameWide(buffer, actual_size)
        })
        .map(clean_dbgeng_path)
        .ok()
        .flatten()
    });

    let process_exe = objects.as_ref().ok().and_then(|objects| unsafe {
        dbgeng_string(|buffer, actual_size| {
            objects.GetCurrentProcessExecutableName(buffer, actual_size)
        })
        .map(clean_dbgeng_path)
        .ok()
        .flatten()
    });

    let module_image = client
        .cast::<IDebugSymbols3>()
        .map_err(|error| error.to_string())
        .and_then(|symbols| unsafe {
            let base = symbols
                .GetModuleByIndex(0)
                .map_err(|error| error.to_string())?;
            dbgeng_string(|buffer, actual_size| {
                symbols.GetModuleNameString(
                    DEBUG_MODNAME_IMAGE,
                    DEBUG_ANY_ID,
                    base,
                    buffer,
                    actual_size,
                )
            })
            .map(clean_dbgeng_path)
        })
        .unwrap_or(None);

    let dump_file_path = client
        .cast::<IDebugClient4>()
        .ok()
        .and_then(|client| capture_base_dump_file_path(&client));

    Ok(DbgEngApiTargetInfo {
        debuggee_class,
        debuggee_qualifier,
        system_server_name,
        process_exe,
        process_exe_wide,
        module_image,
        dump_file_path,
    })
}

fn capture_base_dump_file_path(client: &IDebugClient4) -> Option<String> {
    let count = unsafe { client.GetNumberDumpFiles() }.ok()?;
    for index in 0..count {
        let mut handle = 0u64;
        let mut file_type = 0u32;
        let path = unsafe {
            dbgeng_wide_string(|buffer, actual_size| {
                client.GetDumpFileWide(
                    index,
                    buffer,
                    actual_size,
                    Some(&mut handle as *mut u64),
                    &mut file_type,
                )
            })
        };
        if file_type != DEBUG_DUMP_FILE_BASE {
            continue;
        }
        if let Ok(path) = path
            && let Some(path) = clean_dbgeng_path(path)
        {
            return Some(path);
        }
    }
    None
}

unsafe fn dbgeng_string<F>(mut fill: F) -> Result<String, String>
where
    F: FnMut(Option<&mut [u8]>, Option<*mut u32>) -> windows::core::Result<()>,
{
    let mut buffer = vec![0u8; DBGENG_PATH_BUFFER_SIZE];
    let mut actual_size = 0u32;
    fill(
        Some(buffer.as_mut_slice()),
        Some(&mut actual_size as *mut u32),
    )
    .map_err(|error| error.to_string())?;

    let length = if actual_size > 0 {
        actual_size.saturating_sub(1) as usize
    } else {
        buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len())
    };

    Ok(String::from_utf8_lossy(&buffer[..length.min(buffer.len())]).to_string())
}

unsafe fn dbgeng_wide_string<F>(mut fill: F) -> Result<String, String>
where
    F: FnMut(Option<&mut [u16]>, Option<*mut u32>) -> windows::core::Result<()>,
{
    let mut buffer = vec![0u16; DBGENG_PATH_BUFFER_SIZE];
    let mut actual_size = 0u32;
    fill(
        Some(buffer.as_mut_slice()),
        Some(&mut actual_size as *mut u32),
    )
    .map_err(|error| error.to_string())?;

    let length = if actual_size > 0 {
        actual_size.saturating_sub(1) as usize
    } else {
        buffer
            .iter()
            .position(|word| *word == 0)
            .unwrap_or(buffer.len())
    };

    Ok(String::from_utf16_lossy(
        &buffer[..length.min(buffer.len())],
    ))
}

fn clean_dbgeng_path(path: String) -> Option<String> {
    let value = path.trim().trim_matches('"').to_string();
    if value.is_empty() || value == "?NoImage?" {
        None
    } else {
        Some(value)
    }
}

fn infer_target_kind(
    debuggee_class: Option<u32>,
    debuggee_qualifier: Option<u32>,
    path: Option<&str>,
) -> &'static str {
    if path.is_some_and(|path| kind_for_path(path) == "dump") {
        return "dump";
    }

    match (debuggee_class, debuggee_qualifier) {
        (Some(DEBUG_CLASS_KERNEL), _) => "kernel",
        (
            Some(DEBUG_CLASS_USER_WINDOWS),
            Some(
                DEBUG_USER_WINDOWS_DUMP
                | DEBUG_USER_WINDOWS_SMALL_DUMP
                | DEBUG_USER_WINDOWS_DUMP_WINDOWS_CE,
            ),
        ) => "dump",
        (Some(DEBUG_CLASS_USER_WINDOWS), _) => "user",
        (Some(DEBUG_CLASS_IMAGE_FILE), _) => "dump",
        _ => path.map(kind_for_path).unwrap_or("unknown"),
    }
}

fn choose_better_target_path(current: Option<&str>, candidate: Option<&str>) -> Option<String> {
    let candidate = candidate?.trim();
    if candidate.is_empty() {
        return current.map(str::to_string);
    }
    match current {
        Some(current)
            if looks_like_absolute_path(current) && !looks_like_absolute_path(candidate) =>
        {
            Some(current.to_string())
        }
        Some(current) if current.eq_ignore_ascii_case(candidate) => Some(current.to_string()),
        _ => Some(candidate.to_string()),
    }
}

fn looks_like_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
        || path.starts_with("\\\\")
}

fn parse_debug_transport(summary: &str) -> (Option<String>, Option<String>) {
    if let Some(trans) =
        extract_after(summary, "Trans=@{").and_then(|value| value.split('}').next())
    {
        return parse_transport_clause(trans);
    }

    if let Some(trans) = extract_parenthesized_transport(summary) {
        return parse_transport_clause(trans);
    }

    if looks_like_transport_clause(summary) {
        return parse_transport_clause(summary);
    }

    (None, None)
}

fn parse_transport_clause(text: &str) -> (Option<String>, Option<String>) {
    let text = text.trim().trim_matches('{').trim_matches('}');
    if text.is_empty() || text.eq_ignore_ascii_case("<Local>") {
        return (None, None);
    }

    let (transport, rest) = if let Some(index) = text.find(char::is_whitespace) {
        let (prefix, suffix) = text.split_at(index);
        if is_transport_name(prefix) {
            (Some(prefix.trim().to_string()), suffix.trim())
        } else {
            (None, text)
        }
    } else if let Some((prefix, suffix)) = text.split_once(':') {
        if is_transport_name(prefix) {
            (
                Some(prefix.trim().to_string()),
                suffix.trim_start_matches(':').trim(),
            )
        } else {
            (None, text)
        }
    } else {
        (None, text)
    };

    let server = extract_transport_value(rest, "Server=");
    let port = extract_transport_value(rest, "Port=");
    let pipe = extract_transport_value(rest, "Pipe=");
    let endpoint = match (server, port, pipe) {
        (Some(server), Some(port), _) => Some(format!("{server}:{port}")),
        (_, Some(port), _) => Some(port),
        (_, _, Some(pipe)) => Some(pipe),
        _ if !rest.is_empty() && !rest.contains('=') => Some(rest.to_string()),
        _ => None,
    }
    .map(normalize_observed_endpoint);

    (transport, endpoint)
}

fn is_transport_name(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "tcp"
            | "tcp6"
            | "npipe"
            | "pipe"
            | "spipe"
            | "ssl"
            | "sslpipe"
            | "com"
            | "net"
            | "usb"
            | "1394"
            | "exdi"
            | "serial"
    )
}

fn looks_like_transport_clause(text: &str) -> bool {
    let text = text.trim();
    if let Some((prefix, _)) = text.split_once(':') {
        return is_transport_name(prefix);
    }
    if let Some(index) = text.find(char::is_whitespace) {
        let (prefix, _) = text.split_at(index);
        return is_transport_name(prefix);
    }
    false
}

fn extract_parenthesized_transport(text: &str) -> Option<&str> {
    let end = text.rfind(')')?;
    let start = text[..end].rfind('(')?;
    Some(text[start + 1..end].trim())
}

fn normalize_observed_endpoint(endpoint: String) -> String {
    let endpoint = endpoint.trim().to_string();
    if let Some(rest) = endpoint.strip_prefix("[::ffff:")
        && let Some((ipv4, port)) = rest.split_once("]:")
    {
        return format!("{ipv4}:{port}");
    }
    endpoint
}

fn extract_transport_value(text: &str, key: &str) -> Option<String> {
    extract_after_ignore_case(text, key)
        .and_then(|value| value.split([',', '}']).next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn extract_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let start = text.find(marker)? + marker.len();
    Some(&text[start..])
}

fn extract_after_ignore_case<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let lower_text = text.to_ascii_lowercase();
    let lower_marker = marker.to_ascii_lowercase();
    let start = lower_text.find(&lower_marker)? + marker.len();
    Some(&text[start..])
}

fn kind_for_path(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".dmp") || lower.ends_with(".mdmp") {
        "dump"
    } else {
        "user"
    }
}

fn current_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_info() -> DbgEngApiTargetInfo {
        DbgEngApiTargetInfo {
            debuggee_class: None,
            debuggee_qualifier: None,
            system_server_name: None,
            process_exe: None,
            process_exe_wide: None,
            module_image: None,
            dump_file_path: None,
        }
    }

    #[test]
    fn production_builder_builds_live_user_snapshot() {
        let snapshot = build_current_target_snapshot(
            DbgEngApiTargetInfo {
                debuggee_class: Some(DEBUG_CLASS_USER_WINDOWS),
                debuggee_qualifier: Some(0),
                process_exe: Some("target.exe".to_string()),
                process_exe_wide: Some("C:\\bin\\target.exe".to_string()),
                module_image: Some("target.exe".to_string()),
                ..empty_info()
            },
            456,
        )
        .expect("live snapshot");

        assert_eq!(snapshot.kind, "user");
        assert_eq!(snapshot.name.as_deref(), Some("C:\\bin\\target.exe"));
        assert_eq!(snapshot.source_path, None);
        assert_eq!(snapshot.updated_unix_ms, 456);
    }

    #[test]
    fn production_builder_builds_remote_kernel_transport() {
        let snapshot = build_current_target_snapshot(
            DbgEngApiTargetInfo {
                debuggee_class: Some(DEBUG_CLASS_KERNEL),
                debuggee_qualifier: Some(0),
                system_server_name: Some("tcp:server=192.168.133.132,port=5005".to_string()),
                ..empty_info()
            },
            123,
        )
        .expect("kernel snapshot");

        assert_eq!(snapshot.kind, "kernel");
        assert_eq!(snapshot.transport.as_deref(), Some("tcp"));
        assert_eq!(snapshot.endpoint.as_deref(), Some("192.168.133.132:5005"));
        assert_eq!(snapshot.source_path, None);
    }

    #[test]
    fn production_builder_prefers_enumerated_base_dump_path() {
        let snapshot = build_current_target_snapshot(
            DbgEngApiTargetInfo {
                debuggee_class: Some(DEBUG_CLASS_USER_WINDOWS),
                debuggee_qualifier: Some(DEBUG_USER_WINDOWS_DUMP),
                system_server_name: Some(
                    "Time Travel Debugging: C:\\traces\\target.run".to_string(),
                ),
                process_exe_wide: Some("target.exe".to_string()),
                dump_file_path: Some("C:\\dumps\\target.dmp".to_string()),
                ..empty_info()
            },
            789,
        )
        .expect("dump snapshot");

        assert_eq!(snapshot.kind, "dump");
        assert_eq!(
            snapshot.source_path.as_deref(),
            Some("C:\\dumps\\target.dmp")
        );
        assert_eq!(snapshot.transport, None);
        assert_eq!(snapshot.endpoint, None);
    }

    #[test]
    fn production_builder_never_uses_server_name_as_source_path() {
        let snapshot = build_current_target_snapshot(
            DbgEngApiTargetInfo {
                debuggee_class: Some(DEBUG_CLASS_USER_WINDOWS),
                debuggee_qualifier: Some(0),
                system_server_name: Some(
                    "Time Travel Debugging: C:\\traces\\target.run".to_string(),
                ),
                ..empty_info()
            },
            654,
        )
        .expect("TTD snapshot");

        assert_eq!(snapshot.source_path, None);
        assert_eq!(snapshot.transport, None);
        assert_eq!(snapshot.endpoint, None);
    }

    #[test]
    fn production_builder_returns_none_for_empty_input() {
        assert_eq!(build_current_target_snapshot(empty_info(), 1), None);
    }

    #[test]
    fn transport_helpers_parse_observed_remote_forms() {
        let (transport, endpoint) = parse_debug_transport(
            ".  0 Live user mode: DESKTOP-1V1HKNI (tcp [::ffff:192.168.133.1]:11842)",
        );
        assert_eq!(transport.as_deref(), Some("tcp"));
        assert_eq!(endpoint.as_deref(), Some("192.168.133.1:11842"));

        let (transport, endpoint) = parse_debug_transport(
            "KdSrv:Server=@{<Local>},Trans=@{COM:Port=//./pipe/com_1,Baud=115200}",
        );
        assert_eq!(transport.as_deref(), Some("COM"));
        assert_eq!(endpoint.as_deref(), Some("//./pipe/com_1"));

        assert_eq!(
            parse_debug_transport("Live user mode: <Local>"),
            (None, None)
        );
    }

    #[test]
    fn path_helper_preserves_more_specific_absolute_path() {
        assert_eq!(
            choose_better_target_path(Some("C:\\bin\\target.exe"), Some("target.exe")).as_deref(),
            Some("C:\\bin\\target.exe")
        );
    }

    #[test]
    fn target_snapshot_json_omits_summary() {
        let snapshot = CurrentTargetSnapshot {
            kind: "user".to_string(),
            name: Some("target.exe".to_string()),
            source_path: None,
            transport: None,
            endpoint: None,
            updated_unix_ms: 1,
        };

        let json = serde_json::to_value(snapshot).expect("snapshot json");

        assert!(json.get("summary").is_none());
        assert_eq!(json["name"], "target.exe");
    }
}

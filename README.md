# windbg-mcp-rs

`windbg-mcp-rs` is a pure WinDbg extension DLL that exposes the current debugging session as an MCP server.

- Read official WinDbg command documentation extracted from `docs/debugger.chm`
- Execute WinDbg commands through dbgeng
- Interrupt a running target from MCP
- Use the server from any MCP client over Streamable HTTP

## Screenshots

![WinDbg MCP plugin screenshot 1](images/1.png)

![WinDbg MCP plugin screenshot 2](images/2.png)

## Quick Start

### 1. Install the released extension

**One-liner (recommended):**

```powershell
irm https://raw.githubusercontent.com/kanren3/windbg-mcp-rs/master/scripts/install.ps1 | iex
```

This downloads the latest release from GitHub and installs to all discovered WinDbg locations.  
Run as **Administrator** to install to SDK debugger paths.

### 2. Build the DLL (developers)

```powershell
# x64 (default)
cargo build --release --target x86_64-pc-windows-msvc

# x86 / 32-bit WinDbg
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc

# ARM64
rustup target add aarch64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc
```

Release tags publish one architecture-specific archive for every supported WinDbg engine:

| WinDbg architecture | Rust target | Release suffix | Store DLL destination |
| --- | --- | --- | --- |
| x86 | `i686-pc-windows-msvc` | `windows-x86.zip` | `EngineExtensions32\windbg_mcp_rs.dll` |
| x64 | `x86_64-pc-windows-msvc` | `windows-x64.zip` | `EngineExtensions\windbg_mcp_rs.dll` |
| ARM64 | `aarch64-pc-windows-msvc` | `windows-arm64.zip` | `EngineExtensions\windbg_mcp_rs.dll` |

The checked-in gallery manifest remains architecture-neutral (`Architecture="Any"`). The installer generates Store-only absolute entries for the architectures actually installed. Store gallery package validation requires the loaded DLL file name to match the binary component name, so Store DLLs are always named `windbg_mcp_rs.dll`; architecture is selected by the manifest entry and destination directory. Installation is filtered by host architecture before copying files. On x64 Windows, the installer publishes x86 and x64 entries because WinDbg can use the x86 engine for x86 targets. On ARM64 Windows, the installer publishes only the ARM64 entry by default. Extra SDK directories for non-native architectures are ignored unless they are part of that host architecture set.

### 3. Install a local build

**Install from local build:**

```powershell
.\scripts\install.ps1 -LocalPath .\target
```

`-LocalPath` accepts either a flat directory containing `windbg_mcp_rs.dll` or a build root containing `<RustTarget>\release\windbg_mcp_rs.dll`. The installer reads each DLL's PE machine, rejects mismatched or duplicate candidates, discovers Store packages through `Get-AppxPackage` before falling back to `WindowsApps`, and returns a nonzero exit code if any required architecture fails. Validate without changing installation files with:

```powershell
.\scripts\install.ps1 -LocalPath .\target -DryRun
```

**Manual install:**

```text
# SDK Debuggers
copy target\<RustTarget>\release\windbg_mcp_rs.dll     <matching-windbg>\winext\
copy windbg_mcp_rs_GalleryManifest.xml                 <windbg>\OptionalExtensions\

# WinDbg (Store) — use install.ps1 (manual setup is complex)
# The script rewrites the manifest with absolute architecture-specific paths
# and publishes the shared gallery files.
# atomically under %LOCALAPPDATA%\DBG\ExtRepository\windbg-mcp-rs\.
# Then run:
#   .settings load %LOCALAPPDATA%\DBG\ExtRepository\windbg-mcp-rs\config.xml
#   .settings save
```

### 4. Verify

Start WinDbg and run:

```text
!mcp status
```

The MCP server **auto-starts** when WinDbg reports an active debugging session.  
Endpoint: the first available endpoint from `http://127.0.0.1:50051/mcp` through `http://127.0.0.1:50070/mcp`.

### 5. Connect your MCP client

Run `!mcp status` and point your client to the reported endpoint. For a single instance this is usually:

```text
http://127.0.0.1:50051/mcp
```

## Multi-Instance Discovery

When the default port is already in use, auto-start tries the next localhost port up to `127.0.0.1:50070`. Each running WinDbg instance writes a user-local discovery file:

```text
%LOCALAPPDATA%\windbg-mcp-rs\instances\instance-<pid>.json
```

The JSON file contains the MCP server name and URL, host WinDbg/EngHost process id, host architecture, host process path, start timestamp, and a best-effort `current_target` snapshot for discovery prioritization. In schema 1, `mcp_server_name` and `mcp_server_url` identify the MCP endpoint, `host_pid`, `host_arch`, and `host_process_path` identify the process hosting the MCP extension, while `current_target` uses `name` for the active target image name/path, `source_path` for offline dump/trace source files when available, and `transport`/`endpoint` for remote transports. `current_target` can be `null` during early startup or after the debug session becomes inactive, and is refreshed after WinDbg reports an accessible session or a relevant target/session event. The snapshot is only a hint; clients must still treat registry files as candidates and confirm liveness and target identity with an MCP `initialize` handshake before using the endpoint. The running extension keeps a companion `instance-<pid>.lock` file open to mark the instance as active, and rewrites `instance-<pid>.json` through `instance-<pid>.json.tmp` followed by an atomic replace. When another instance starts, it tries to delete old `instance-*.lock`, `instance-*.json`, and `instance-*.json.tmp` groups; active instances remain protected by their lock file, while stale files from crashed or killed WinDbg processes are normally removed.

## WinDbg Commands

Use `!mcp help` to list all plugin commands.

Common ones:

```text
!mcp help
!mcp serve 127.0.0.1:50051
!mcp status
!mcp catalog dt
!mcp doc dt
!mcp stop
```

## What MCP Exposes

- `Resources`: a low-context guide resource and compact/full WinDbg command documentation resources
- `Tools`: a compact toolset for catalog search, execution-state query, command execution, and target interrupt

Pure UI shortcut topics remain available as documentation, and command execution is exposed through a single `windbg_execute_command` tool.

Recommended agent flow: call `windbg_search_catalog`, read `windbg://command/{id}`, fall back to `windbg://command-full/{id}` only when needed, call `windbg_get_execution_state`, and then call `windbg_execute_command`.

If the debugger is running or busy, call `windbg_interrupt_target` explicitly and verify state again before executing the command.

## Development

```powershell
cargo check
cargo test
```

## Notes

- This project was written entirely with a Vibe Coding workflow
- The server runs inside the WinDbg process
- The runtime does not parse `docs/debugger.chm`; it uses the prebuilt static catalog in `src/catalog.json`
- The transport is Streamable HTTP
- Set your MCP client timeout as high as possible, because some WinDbg operations can take a long time to finish
- The server now auto-starts when WinDbg reports an active debugging session. Run `!mcp stop` to stop it, or `!mcp serve` to start it again manually.
- `windbg_mcp_rs_GalleryManifest.xml` enables WinDbg auto-loading when placed in `OptionalExtensions\` alongside the extension DLL.
- Use `scripts\install.ps1` to automatically deploy the extension to all discovered WinDbg installations.

<#
.SYNOPSIS
    Installs windbg-mcp-rs for every discovered WinDbg architecture.

.DESCRIPTION
    Discovers SDK and Store WinDbg engines, validates each extension DLL's PE
    machine, and installs architecture-matched DLLs and gallery manifests.

.PARAMETER LocalPath
    Local directory containing windbg_mcp_rs.dll or Rust target release builds.

.PARAMETER Version
    GitHub release version without the leading v. Defaults to the latest release.

.PARAMETER DryRun
    Validates discovery, DLLs, paths, and manifests without writing installation files.
#>

[CmdletBinding()]
param(
    [string]$LocalPath,
    [string]$Version,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$script:ScriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { "" }
$script:RepoOwner = "kanren3"
$script:RepoName = "windbg-mcp-rs"
$script:TempDir = Join-Path $env:TEMP "windbg-mcp-rs-install"

$script:ArchitectureTable = @(
    [pscustomobject]@{
        Name = "x86"
        RustTarget = "i686-pc-windows-msvc"
        ReleaseAssetSuffix = "x86"
        StorePackageDirectory = "x86"
        StoreExtensionDirectory = "EngineExtensions32"
        StoreDllName = "windbg_mcp_rs.dll"
        ManifestArchitecture = "x86"
        PeMachine = [uint16]0x014C
        Order = 1
    },
    [pscustomobject]@{
        Name = "x64"
        RustTarget = "x86_64-pc-windows-msvc"
        ReleaseAssetSuffix = "x64"
        StorePackageDirectory = "amd64"
        StoreExtensionDirectory = "EngineExtensions"
        StoreDllName = "windbg_mcp_rs.dll"
        ManifestArchitecture = "amd64"
        PeMachine = [uint16]0x8664
        Order = 2
    },
    [pscustomobject]@{
        Name = "arm64"
        RustTarget = "aarch64-pc-windows-msvc"
        ReleaseAssetSuffix = "arm64"
        StorePackageDirectory = "arm64"
        StoreExtensionDirectory = "EngineExtensions"
        StoreDllName = "windbg_mcp_rs.dll"
        ManifestArchitecture = "arm64"
        PeMachine = [uint16]0xAA64
        Order = 3
    }
)
$ArchitectureTable = $script:ArchitectureTable
if (-not ("WindbgMcpInstaller.NativeMethods" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace WindbgMcpInstaller
{
    public static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(
            string existingFileName,
            string newFileName,
            uint flags);
    }
}
"@
}


function Get-ArchitectureByName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $match = @($script:ArchitectureTable | Where-Object { $_.Name -eq $Name })
    if ($match.Count -ne 1) {
        throw "Unsupported architecture name '$Name'."
    }
    return $match[0]
}

function Get-ArchitectureByPeMachine {
    param([Parameter(Mandatory = $true)][uint16]$PeMachine)

    $match = @($script:ArchitectureTable | Where-Object { $_.PeMachine -eq $PeMachine })
    if ($match.Count -ne 1) {
        throw ("Unsupported PE machine 0x{0:X4}." -f $PeMachine)
    }
    return $match[0]
}

function Convert-ArchitectureAlias {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    switch ($Name.Trim().ToLowerInvariant()) {
        "x86" { return "x86" }
        "i386" { return "x86" }
        "i686" { return "x86" }
        "x64" { return "x64" }
        "amd64" { return "x64" }
        "arm64" { return "arm64" }
        "aarch64" { return "arm64" }
        default { return $null }
    }
}

function Get-NativeWindowsArchitectureName {
    $raw = if (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITEW6432)) {
        $env:PROCESSOR_ARCHITEW6432
    }
    else {
        $env:PROCESSOR_ARCHITECTURE
    }

    $architecture = Convert-ArchitectureAlias -Name $raw
    if (-not $architecture) {
        throw "Unsupported native Windows architecture '$raw'."
    }
    return $architecture
}

function Get-WinDbgArchitecturesForHost {
    param([string]$HostArchitecture)

    $architecture = Convert-ArchitectureAlias -Name $HostArchitecture
    if (-not $architecture) {
        $architecture = Get-NativeWindowsArchitectureName
    }

    if ($architecture -eq "x64") {
        return @(
            Get-ArchitectureByName -Name "x86"
            Get-ArchitectureByName -Name "x64"
        )
    }

    return @(Get-ArchitectureByName -Name $architecture)
}

function Get-StoreArchitecturesForPackage {
    param([string]$PackageArchitecture)

    return @(Get-WinDbgArchitecturesForHost -HostArchitecture $PackageArchitecture)
}

function Get-StorePackageArchitectureName {
    param(
        [object]$Package,
        [Parameter(Mandatory = $true)][string]$Path
    )

    foreach ($propertyName in @("Architecture", "ProcessorArchitecture")) {
        if ($Package -and ($Package.PSObject.Properties.Name -contains $propertyName)) {
            $architecture = Convert-ArchitectureAlias -Name ([string]$Package.$propertyName)
            if ($architecture) { return $architecture }
        }
    }

    $leafName = Split-Path -Leaf $Path
    if ($leafName -match '_(x86|x64|arm64)__') {
        return (Convert-ArchitectureAlias -Name $Matches[1])
    }
    if ($leafName -match '_(x86|x64|arm64)_') {
        return (Convert-ArchitectureAlias -Name $Matches[1])
    }

    return Get-NativeWindowsArchitectureName
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -lt 64) {
            throw "PE file '$Path' is shorter than the DOS header."
        }
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "PE file '$Path' has an invalid DOS signature."
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or ([int64]$peOffset + 6) -gt $stream.Length) {
            throw "PE file '$Path' has an invalid e_lfanew offset."
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "PE file '$Path' has an invalid PE signature."
        }
        $machine = $reader.ReadUInt16()
        $null = Get-ArchitectureByPeMachine -PeMachine $machine
        return $machine
    }
    finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
}

function Get-StorePackageRoots {
    param(
        [object[]]$AppxPackages,
        [string]$WindowsAppsRoot = (Join-Path ${env:ProgramFiles} "WindowsApps")
    )

    $packagesWereInjected = $PSBoundParameters.ContainsKey("AppxPackages")
    if (-not $packagesWereInjected) {
        $appxCommand = Get-Command Get-AppxPackage -ErrorAction SilentlyContinue
        if ($appxCommand) {
            $AppxPackages = @(Get-AppxPackage -Name Microsoft.WinDbg -ErrorAction SilentlyContinue)
        }
        else {
            $AppxPackages = @()
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $appxRoots = [System.Collections.Generic.List[object]]::new()
    foreach ($package in @($AppxPackages)) {
        $location = [string]$package.InstallLocation
        if ([string]::IsNullOrWhiteSpace($location) -or -not (Test-Path -LiteralPath $location -PathType Container)) {
            continue
        }
        $normalized = (Resolve-Path -LiteralPath $location).Path
        $hasEngine = $false
        foreach ($architecture in $script:ArchitectureTable) {
            $engine = Join-Path (Join-Path $normalized $architecture.StorePackageDirectory) "dbgeng.dll"
            if (Test-Path -LiteralPath $engine -PathType Leaf) {
                $hasEngine = $true
                break
            }
        }
        if ($hasEngine -and $seen.Add($normalized)) {
            try { $versionKey = [version]$package.Version }
            catch { $versionKey = [version]"0.0" }
            $appxRoots.Add([pscustomobject]@{
                Path = $normalized
                Architecture = Get-StorePackageArchitectureName -Package $package -Path $normalized
                Version = [string]$package.Version
                VersionKey = $versionKey
            }) | Out-Null
        }
    }
    if ($appxRoots.Count -gt 0) {
        return @($appxRoots | Sort-Object VersionKey -Descending)
    }

    $fallbackRoots = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -LiteralPath $WindowsAppsRoot -PathType Container) {
        foreach ($directory in @(Get-ChildItem -LiteralPath $WindowsAppsRoot -Directory -Filter "Microsoft.WinDbg_*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
            $normalized = $directory.FullName
            $hasEngine = $false
            foreach ($architecture in $script:ArchitectureTable) {
                $engine = Join-Path (Join-Path $normalized $architecture.StorePackageDirectory) "dbgeng.dll"
                if (Test-Path -LiteralPath $engine -PathType Leaf) {
                    $hasEngine = $true
                    break
                }
            }
            if ($hasEngine -and $seen.Add($normalized)) {
                $versionText = if ($directory.Name -match '^Microsoft\.WinDbg_([0-9.]+)_') { $Matches[1] } else { "0.0" }
                try { $versionKey = [version]$versionText }
                catch { $versionKey = [version]"0.0" }
                $fallbackRoots.Add([pscustomobject]@{
                    Path = $normalized
                    Architecture = Get-StorePackageArchitectureName -Path $normalized
                    Version = $directory.Name
                    VersionKey = $versionKey
                }) | Out-Null
            }
        }
    }
    return @($fallbackRoots | Sort-Object VersionKey -Descending)
}

function Find-WinDbgInstallations {
    param(
        [string[]]$SdkRoots,
        [object[]]$StorePackageRoots,
        [string]$StoreBasePath = (Join-Path $env:LOCALAPPDATA "DBG"),
        [string]$HostArchitecture
    )

    if (-not $PSBoundParameters.ContainsKey("SdkRoots")) {
        $discoveredSdkRoots = [System.Collections.Generic.List[string]]::new()
        $defaultSdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Debuggers"
        if (Test-Path -LiteralPath $defaultSdkRoot -PathType Container) {
            $discoveredSdkRoots.Add($defaultSdkRoot) | Out-Null
        }
        foreach ($registryPath in @(
            "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots"
        )) {
            $kitsRoot = (Get-ItemProperty -Path $registryPath -Name KitsRoot10 -ErrorAction SilentlyContinue).KitsRoot10
            if ($kitsRoot) {
                $debuggers = Join-Path $kitsRoot "Debuggers"
                if (Test-Path -LiteralPath $debuggers -PathType Container) {
                    $discoveredSdkRoots.Add($debuggers) | Out-Null
                }
            }
        }
        $SdkRoots = @($discoveredSdkRoots)
    }
    if (-not $PSBoundParameters.ContainsKey("StorePackageRoots")) {
        $StorePackageRoots = @(Get-StorePackageRoots)
    }

    $found = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $sdkArchitectures = @(Get-WinDbgArchitecturesForHost -HostArchitecture $HostArchitecture)
    foreach ($sdkRoot in @($SdkRoots)) {
        if (-not (Test-Path -LiteralPath $sdkRoot -PathType Container)) { continue }
        foreach ($architecture in $sdkArchitectures) {
            $engineRoot = Join-Path $sdkRoot $architecture.Name
            if (-not (Test-Path -LiteralPath (Join-Path $engineRoot "dbgeng.dll") -PathType Leaf)) { continue }
            $normalized = (Resolve-Path -LiteralPath $engineRoot).Path
            $key = "SDK|$normalized|$($architecture.Name)"
            if ($seen.Add($key)) {
                $found.Add([pscustomobject]@{
                    Path = $normalized
                    Architecture = $architecture
                    Label = "SDK Debuggers ($($architecture.Name))"
                    Type = "SDK"
                    PackageRoot = $null
                }) | Out-Null
            }
        }
    }

    $storePath = [IO.Path]::GetFullPath($StoreBasePath)
    foreach ($package in @($StorePackageRoots)) {
        $packagePath = if ($package -is [string]) { $package } else { [string]$package.Path }
        if ([string]::IsNullOrWhiteSpace($packagePath)) { continue }
        $packageArchitecture = if ($package -is [string]) {
            Get-StorePackageArchitectureName -Path $packagePath
        }
        elseif ($package.PSObject.Properties.Name -contains "Architecture") {
            [string]$package.Architecture
        }
        else {
            Get-StorePackageArchitectureName -Path $packagePath
        }
        foreach ($architecture in @(Get-StoreArchitecturesForPackage -PackageArchitecture $packageArchitecture)) {
            $engine = Join-Path (Join-Path $packagePath $architecture.StorePackageDirectory) "dbgeng.dll"
            if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { continue }
            $key = "Store|$storePath|$($architecture.Name)"
            if ($seen.Add($key)) {
                $found.Add([pscustomobject]@{
                    Path = $storePath
                    Architecture = $architecture
                    Label = "WinDbg (Store, $($architecture.Name))"
                    Type = "Store"
                    PackageRoot = $packagePath
                }) | Out-Null
            }
        }
    }

    return @($found | Sort-Object @{ Expression = { $_.Architecture.Order } }, Type, Path)
}

function Resolve-LocalDlls {
    param([Parameter(Mandatory = $true)][string]$LocalPath)

    $root = (Resolve-Path -LiteralPath $LocalPath -ErrorAction Stop).Path
    $candidates = [System.Collections.Generic.List[object]]::new()
    $flatPath = Join-Path $root "windbg_mcp_rs.dll"
    if (Test-Path -LiteralPath $flatPath -PathType Leaf) {
        $machine = Get-PeMachine -Path $flatPath
        $candidates.Add([pscustomobject]@{
            Architecture = Get-ArchitectureByPeMachine -PeMachine $machine
            Dll = (Resolve-Path -LiteralPath $flatPath).Path
            Source = "flat"
        }) | Out-Null
    }

    foreach ($expectedArchitecture in $script:ArchitectureTable) {
        $matrixPath = Join-Path $root (Join-Path $expectedArchitecture.RustTarget "release\windbg_mcp_rs.dll")
        if (-not (Test-Path -LiteralPath $matrixPath -PathType Leaf)) { continue }
        $machine = Get-PeMachine -Path $matrixPath
        $actualArchitecture = Get-ArchitectureByPeMachine -PeMachine $machine
        if ($actualArchitecture.Name -ne $expectedArchitecture.Name) {
            throw "Matrix DLL architecture mismatch: '$matrixPath' is $($actualArchitecture.Name), expected $($expectedArchitecture.Name)."
        }
        $candidates.Add([pscustomobject]@{
            Architecture = $expectedArchitecture
            Dll = (Resolve-Path -LiteralPath $matrixPath).Path
            Source = "matrix"
        }) | Out-Null
    }

    $resolved = @{}
    foreach ($architecture in $script:ArchitectureTable) {
        $matches = @($candidates | Where-Object { $_.Architecture.Name -eq $architecture.Name })
        if ($matches.Count -gt 1) {
            throw "Multiple DLLs found for architecture '$($architecture.Name)': $($matches.Dll -join ', ')."
        }
        if ($matches.Count -eq 1) {
            $resolved[$architecture.Name] = $matches[0]
        }
    }
    if ($resolved.Count -eq 0) {
        throw "No DLL found. Checked flat '<LocalPath>\windbg_mcp_rs.dll' and matrix '<LocalPath>\<RustTarget>\release\windbg_mcp_rs.dll' layouts."
    }
    return $resolved
}

function Get-StoreDllPath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][object]$Architecture
    )

    return Join-Path (Join-Path $BasePath $Architecture.StoreExtensionDirectory) $Architecture.StoreDllName
}

function New-StoreGalleryManifest {
    param(
        [Parameter(Mandatory = $true)][string]$TemplatePath,
        [Parameter(Mandatory = $true)][object[]]$StoreEntries
    )

    if ($StoreEntries.Count -eq 0) { throw "Store manifest entries cannot be empty." }
    $duplicates = @($StoreEntries | Group-Object { $_.Architecture.Name } | Where-Object { $_.Count -ne 1 })
    if ($duplicates.Count -gt 0) { throw "Store manifest architectures must be unique." }

    $content = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $TemplatePath).Path)
    $placeholder = '<File Architecture="Any" Module="winext\windbg_mcp_rs.dll" FilePathKind="RepositoryRelative" />'
    $matches = [regex]::Matches($content, [regex]::Escape($placeholder))
    if ($matches.Count -ne 1) {
        throw 'Gallery manifest template must contain exactly one Architecture="Any" repository-relative placeholder.'
    }

    $lines = foreach ($entry in @($StoreEntries | Sort-Object { $_.Architecture.Order })) {
        $modulePath = [IO.Path]::GetFullPath([string]$entry.ModulePath)
        $escapedModule = [Security.SecurityElement]::Escape($modulePath)
        '          <File Architecture="{0}" Module="{1}" FilePathKind="Absolute" />' -f $entry.Architecture.ManifestArchitecture, $escapedModule
    }
    $replacement = $lines -join "`r`n"
    $match = $matches[0]
    return $content.Substring(0, $match.Index) + $replacement + $content.Substring($match.Index + $match.Length)
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Publish-AtomicFile {
    param(
        [Parameter(Mandatory = $true)][string]$TempPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    # MOVEFILE_REPLACE_EXISTING (0x1) keeps the old file on rename failure.
    # MOVEFILE_WRITE_THROUGH (0x8) flushes the same-volume publication to disk.
    $moveFlags = [uint32](0x1 -bor 0x8)
    if (-not [WindbgMcpInstaller.NativeMethods]::MoveFileEx($TempPath, $DestinationPath, $moveFlags)) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [ComponentModel.Win32Exception]::new(
            $errorCode,
            "Atomic publication from '$TempPath' to '$DestinationPath' failed."
        )
    }
}

function Invoke-StoreManifestTransaction {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][object[]]$PendingEntries,
        [Parameter(Mandatory = $true)][string]$TemplatePath,
        [switch]$DryRun,
        [scriptblock]$BeforeManifestCommit
    )

    if ($PendingEntries.Count -eq 0) {
        return [pscustomobject]@{ Installed = 0; Failed = 0; Validated = 0; Published = $false; ConfigPath = $null }
    }
    $duplicateArchitectures = @($PendingEntries | Group-Object { $_.Architecture.Name } | Where-Object { $_.Count -ne 1 })
    if ($duplicateArchitectures.Count -gt 0) {
        throw "Pending Store architectures must be unique."
    }

    $validEntries = [System.Collections.Generic.List[object]]::new()
    $validationFailures = 0
    foreach ($entry in $PendingEntries) {
        try {
            if (-not (Test-Path -LiteralPath $entry.SourceDll -PathType Leaf)) {
                throw "Source DLL does not exist: $($entry.SourceDll)"
            }
            $machine = Get-PeMachine -Path $entry.SourceDll
            $actual = Get-ArchitectureByPeMachine -PeMachine $machine
            if ($actual.Name -ne $entry.Architecture.Name) {
                throw "Source DLL '$($entry.SourceDll)' is $($actual.Name), expected $($entry.Architecture.Name)."
            }
            $validEntries.Add([pscustomobject]@{
                Architecture = $entry.Architecture
                SourceDll = (Resolve-Path -LiteralPath $entry.SourceDll).Path
                ModulePath = [IO.Path]::GetFullPath((Get-StoreDllPath -BasePath $BasePath -Architecture $entry.Architecture))
            }) | Out-Null
        }
        catch {
            Write-Host "  [!] WinDbg (Store, $($entry.Architecture.Name)): $($_.Exception.Message)" -ForegroundColor Red
            $validationFailures++
        }
    }
    if ($validEntries.Count -eq 0) {
        return [pscustomobject]@{ Installed = 0; Failed = $PendingEntries.Count; Validated = 0; Published = $false; ConfigPath = $null }
    }

    $null = New-StoreGalleryManifest -TemplatePath $TemplatePath -StoreEntries @($validEntries)
    if ($DryRun) {
        return [pscustomobject]@{
            Installed = 0
            Failed = $validationFailures
            Validated = $validEntries.Count
            Published = $false
            ConfigPath = [IO.Path]::GetFullPath((Join-Path $BasePath "ExtRepository\windbg-mcp-rs\config.xml"))
        }
    }

    $copiedEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $validEntries) {
        try {
            $dllDirectory = Split-Path -Parent $entry.ModulePath
            New-Item -ItemType Directory -Path $dllDirectory -Force | Out-Null
            Copy-Item -LiteralPath $entry.SourceDll -Destination $entry.ModulePath -Force
            $copiedMachine = Get-PeMachine -Path $entry.ModulePath
            $copiedArchitecture = Get-ArchitectureByPeMachine -PeMachine $copiedMachine
            if ($copiedArchitecture.Name -ne $entry.Architecture.Name) {
                throw "Copied DLL is $($copiedArchitecture.Name), expected $($entry.Architecture.Name)."
            }
            $copiedEntries.Add($entry) | Out-Null
        }
        catch {
            Write-Host "  [!] WinDbg (Store, $($entry.Architecture.Name)): copy failed - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    if ($copiedEntries.Count -eq 0) {
        return [pscustomobject]@{ Installed = 0; Failed = $PendingEntries.Count; Validated = 0; Published = $false; ConfigPath = $null }
    }

    $galleryDirectory = Join-Path $BasePath "ExtRepository\windbg-mcp-rs"
    $configPath = Join-Path $galleryDirectory "config.xml"
    $versionPath = Join-Path $galleryDirectory "ManifestVersion.txt"
    $manifestPath = Join-Path $galleryDirectory "manifest.1.xml"
    $configTemp = "$configPath.tmp"
    $versionTemp = "$versionPath.tmp"
    $manifestTemp = "$manifestPath.tmp"
    try {
        New-Item -ItemType Directory -Path $galleryDirectory -Force | Out-Null
        $manifestContent = New-StoreGalleryManifest -TemplatePath $TemplatePath -StoreEntries @($copiedEntries)
        $escapedGalleryDirectory = [Security.SecurityElement]::Escape([IO.Path]::GetFullPath($galleryDirectory))
        $configGuid = [Guid]::NewGuid().ToString("B")
        $configContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Settings Version="1">
  <Namespace Name="Extensions">
    <Setting Name="ExtensionRepository" Type="VT_BSTR" Value="Implicit"></Setting>
    <Namespace Name="ExtensionRepositories">
      <Namespace Name="windbg-mcp-rs">
        <Setting Name="Id" Type="VT_BSTR" Value="$configGuid"></Setting>
        <Setting Name="LocalCacheRootFolder" Type="VT_BSTR" Value="$escapedGalleryDirectory"></Setting>
        <Setting Name="IsEnabled" Type="VT_BOOL" Value="true"></Setting>
      </Namespace>
    </Namespace>
  </Namespace>
</Settings>
"@
        $manifestBuild = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $versionContent = "1`r`n1.0.0.0`r`n$manifestBuild`r`n"

        Write-Utf8File -Path $configTemp -Content $configContent
        Write-Utf8File -Path $versionTemp -Content $versionContent
        Write-Utf8File -Path $manifestTemp -Content $manifestContent
        Publish-AtomicFile -TempPath $configTemp -DestinationPath $configPath
        Publish-AtomicFile -TempPath $versionTemp -DestinationPath $versionPath
        if ($BeforeManifestCommit) { & $BeforeManifestCommit $manifestPath }
        Publish-AtomicFile -TempPath $manifestTemp -DestinationPath $manifestPath

        return [pscustomobject]@{
            Installed = $copiedEntries.Count
            Failed = $PendingEntries.Count - $copiedEntries.Count
            Validated = 0
            Published = $true
            ConfigPath = $configPath
        }
    }
    catch {
        foreach ($tempPath in @($configTemp, $versionTemp, $manifestTemp)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  [!] WinDbg (Store): manifest transaction failed - $($_.Exception.Message)" -ForegroundColor Red
        return [pscustomobject]@{
            Installed = 0
            Failed = $PendingEntries.Count
            Validated = 0
            Published = $false
            ConfigPath = $null
        }
    }
}

function Invoke-SdkInstallation {
    param(
        [Parameter(Mandatory = $true)][object]$Installation,
        [Parameter(Mandatory = $true)][string]$SourceDll,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [switch]$DryRun
    )

    try {
        $sourceMachine = Get-PeMachine -Path $SourceDll
        $sourceArchitecture = Get-ArchitectureByPeMachine -PeMachine $sourceMachine
        if ($sourceArchitecture.Name -ne $Installation.Architecture.Name) {
            throw "DLL is $($sourceArchitecture.Name), expected $($Installation.Architecture.Name)."
        }
        [xml]$null = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ManifestPath).Path)
        if ($DryRun) {
            return [pscustomobject]@{ Installed = 0; Failed = 0; Validated = 1 }
        }

        $dllDirectory = Join-Path $Installation.Path "winext"
        $manifestDirectory = Join-Path $Installation.Path "OptionalExtensions"
        New-Item -ItemType Directory -Path $dllDirectory -Force | Out-Null
        New-Item -ItemType Directory -Path $manifestDirectory -Force | Out-Null
        $dllDestination = Join-Path $dllDirectory "windbg_mcp_rs.dll"
        Copy-Item -LiteralPath $SourceDll -Destination $dllDestination -Force
        $copiedMachine = Get-PeMachine -Path $dllDestination
        if ($copiedMachine -ne $Installation.Architecture.PeMachine) {
            throw "Copied DLL PE machine does not match $($Installation.Architecture.Name)."
        }
        Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $manifestDirectory "windbg_mcp_rs_GalleryManifest.xml") -Force
        return [pscustomobject]@{ Installed = 1; Failed = 0; Validated = 0 }
    }
    catch {
        Write-Host "  [!] $($Installation.Label): $($_.Exception.Message)" -ForegroundColor Red
        return [pscustomobject]@{ Installed = 0; Failed = 1; Validated = 0 }
    }
}

function Resolve-ReleaseDlls {
    param(
        [Parameter(Mandatory = $true)][object[]]$Architectures,
        [string]$Version
    )

    $releaseUrl = if ($Version) {
        "https://api.github.com/repos/$script:RepoOwner/$script:RepoName/releases/tags/v$Version"
    }
    else {
        "https://api.github.com/repos/$script:RepoOwner/$script:RepoName/releases/latest"
    }
    $release = Invoke-RestMethod -Uri $releaseUrl -ErrorAction Stop
    New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
    $resolved = @{}
    foreach ($architecture in @($Architectures | Sort-Object Order)) {
        try {
            $asset = @($release.assets | Where-Object { $_.name -like "*-windows-$($architecture.ReleaseAssetSuffix).zip" }) | Select-Object -First 1
            if (-not $asset) { throw "Release asset for $($architecture.Name) is missing." }
            $architectureTemp = Join-Path $script:TempDir $architecture.Name
            New-Item -ItemType Directory -Path $architectureTemp -Force | Out-Null
            $zipPath = Join-Path $architectureTemp "release.zip"
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
            Expand-Archive -LiteralPath $zipPath -DestinationPath $architectureTemp -Force
            $dll = Get-ChildItem -LiteralPath $architectureTemp -Recurse -File -Filter "windbg_mcp_rs.dll" | Select-Object -First 1
            $manifest = Get-ChildItem -LiteralPath $architectureTemp -Recurse -File -Filter "windbg_mcp_rs_GalleryManifest.xml" | Select-Object -First 1
            if (-not $dll) { throw "Release asset for $($architecture.Name) contains no windbg_mcp_rs.dll." }
            if (-not $manifest) { throw "Release asset for $($architecture.Name) contains no gallery manifest." }
            $machine = Get-PeMachine -Path $dll.FullName
            if ($machine -ne $architecture.PeMachine) {
                throw "Release asset suffix $($architecture.ReleaseAssetSuffix) contains the wrong PE machine."
            }
            $resolved[$architecture.Name] = [pscustomobject]@{
                Architecture = $architecture
                Dll = $dll.FullName
                Manifest = $manifest.FullName
            }
        }
        catch {
            Write-Host "  [!] $($architecture.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    return $resolved
}

function Invoke-WindbgMcpInstall {
    [CmdletBinding()]
    param(
        [string]$LocalPath,
        [string]$Version,
        [switch]$DryRun
    )

    $installations = @(Find-WinDbgInstallations)
    if ($installations.Count -eq 0) {
        throw "No WinDbg installations found. Store discovery requires a Microsoft.WinDbg package with a usable engine."
    }
    Write-Host "Found $($installations.Count) WinDbg installation(s):" -ForegroundColor Green
    foreach ($installation in $installations) { Write-Host "  $($installation.Label)" -ForegroundColor Gray }

    $requiredArchitectures = @($installations | ForEach-Object { $_.Architecture } | Group-Object Name | ForEach-Object { $_.Group[0] } | Sort-Object Order)

    $dllByArchitecture = @{}
    if ($LocalPath) {
        # The repo-local manifest template is only needed for local builds; the
        # release path extracts the manifest from each downloaded architecture
        # archive. Resolving it unconditionally breaks the irm | iex one-liner,
        # where $script:ScriptDir is empty and there is no repo checkout.
        $manifestTemplate = Join-Path $script:ScriptDir "..\windbg_mcp_rs_GalleryManifest.xml"
        if (-not (Test-Path -LiteralPath $manifestTemplate -PathType Leaf)) {
            throw "Gallery manifest template not found at '$manifestTemplate'."
        }
        Write-Host "=== windbg-mcp-rs Installer (local) ===" -ForegroundColor Cyan
        $localDlls = Resolve-LocalDlls -LocalPath $LocalPath
        foreach ($name in $localDlls.Keys) {
            $dllByArchitecture[$name] = [pscustomobject]@{
                Architecture = $localDlls[$name].Architecture
                Dll = $localDlls[$name].Dll
                Manifest = (Resolve-Path -LiteralPath $manifestTemplate).Path
            }
        }
    }
    else {
        Write-Host "=== windbg-mcp-rs Installer ===" -ForegroundColor Cyan
        $dllByArchitecture = Resolve-ReleaseDlls -Architectures $requiredArchitectures -Version $Version
    }

    $failed = 0
    foreach ($architecture in $requiredArchitectures) {
        if (-not $dllByArchitecture.ContainsKey($architecture.Name)) {
            Write-Host "  [!] No validated DLL for required architecture $($architecture.Name)." -ForegroundColor Red
            $failed++
        }
    }
    $availableRequired = @($requiredArchitectures | Where-Object { $dllByArchitecture.ContainsKey($_.Name) })
    if ($availableRequired.Count -eq 0) {
        throw "No required DLLs available. Checked flat, matrix, and release asset sources."
    }

    $installed = 0
    $validated = 0
    $sdkInstalled = 0
    $storeInstalled = 0
    $storeConfigPaths = [System.Collections.Generic.List[string]]::new()

    foreach ($installation in @($installations | Where-Object { $_.Type -eq "SDK" })) {
        if (-not $dllByArchitecture.ContainsKey($installation.Architecture.Name)) { continue }
        $files = $dllByArchitecture[$installation.Architecture.Name]
        $result = Invoke-SdkInstallation -Installation $installation -SourceDll $files.Dll -ManifestPath $files.Manifest -DryRun:$DryRun
        $installed += $result.Installed
        $sdkInstalled += $result.Installed
        $validated += $result.Validated
        $failed += $result.Failed
        if ($result.Installed -gt 0) { Write-Host "  [+] $($installation.Label): installed" -ForegroundColor Green }
    }

    foreach ($group in @($installations | Where-Object { $_.Type -eq "Store" } | Group-Object Path)) {
        $pending = [System.Collections.Generic.List[object]]::new()
        $template = $null
        foreach ($installation in $group.Group) {
            if (-not $dllByArchitecture.ContainsKey($installation.Architecture.Name)) { continue }
            $files = $dllByArchitecture[$installation.Architecture.Name]
            $pending.Add([pscustomobject]@{
                Architecture = $installation.Architecture
                SourceDll = $files.Dll
            }) | Out-Null
            if (-not $template) { $template = $files.Manifest }
        }
        if ($pending.Count -eq 0) { continue }
        $transaction = Invoke-StoreManifestTransaction -BasePath $group.Name -PendingEntries @($pending) -TemplatePath $template -DryRun:$DryRun
        $installed += $transaction.Installed
        $storeInstalled += $transaction.Installed
        $validated += $transaction.Validated
        $failed += $transaction.Failed
        if ($transaction.Published -and $transaction.ConfigPath) {
            $storeConfigPaths.Add($transaction.ConfigPath) | Out-Null
        }
    }

    Write-Host ""
    Write-Host "=== Installation Summary ===" -ForegroundColor Cyan
    Write-Host "  Installed: $installed" -ForegroundColor Green
    if ($DryRun) { Write-Host "  Validated: $validated" -ForegroundColor Green }
    if ($failed -gt 0) { Write-Host "  Failed:    $failed" -ForegroundColor Red }
    Write-Host ""
    if ($storeInstalled -gt 0) {
        foreach ($configPath in $storeConfigPaths) {
            Write-Host "WinDbg (Store): run once to enable auto-load:" -ForegroundColor Yellow
            Write-Host "  .settings load $configPath" -ForegroundColor White
            Write-Host "  .settings save" -ForegroundColor White
        }
    }
    if ($sdkInstalled -gt 0) {
        Write-Host "SDK Debuggers: gallery manifest auto-loads on restart. Run '!mcp status'." -ForegroundColor Yellow
    }
    if ($installed -gt 0) {
        Write-Host "Server uses the first available endpoint in http://127.0.0.1:50051-50070/mcp." -ForegroundColor Gray
    }

    return [pscustomobject]@{
        Installed = $installed
        Failed = $failed
        Validated = $validated
        SdkInstalled = $sdkInstalled
        StoreInstalled = $storeInstalled
        StoreConfigPaths = @($storeConfigPaths)
    }
}

function Get-InstallerExitCode {
    param([Parameter(Mandatory = $true)][object]$Result)

    if ([int]$Result.Failed -gt 0) { return 1 }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = 0
    try {
        $result = Invoke-WindbgMcpInstall -LocalPath $LocalPath -Version $Version -DryRun:$DryRun
        $exitCode = Get-InstallerExitCode -Result $result
    }
    catch {
        Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
        $exitCode = 1
    }
    finally {
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit $exitCode
}

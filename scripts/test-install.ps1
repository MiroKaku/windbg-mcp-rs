[CmdletBinding()]
param(
    [string]$BuildRoot
)

$ErrorActionPreference = "Stop"
$script:TestScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $script:TestScriptDir "install.ps1")

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Assert-Equal {
    param(
        $Actual,
        $Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if ($Actual -ne $Expected) {
        throw "Assertion failed: $Message. Expected '$Expected', got '$Actual'."
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$MessagePattern
    )
    $threw = $false
    try { & $Action }
    catch {
        $threw = $true
        if ($_.Exception.Message -notlike "*$MessagePattern*") {
            throw "Expected error containing '$MessagePattern', got '$($_.Exception.Message)'."
        }
    }
    if (-not $threw) { throw "Expected error containing '$MessagePattern'." }
}

function New-TestFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    [IO.File]::WriteAllBytes($Path, [byte[]]::new(1))
}

function New-TestPe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][uint16]$Machine
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $bytes = [byte[]]::new(512)
    [BitConverter]::GetBytes([uint16]0x5A4D).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([int32]0x80).CopyTo($bytes, 0x3C)
    [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($bytes, 0x80)
    [BitConverter]::GetBytes($Machine).CopyTo($bytes, 0x84)
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function New-EngineFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Subdirectory
    )
    New-TestFile -Path (Join-Path (Join-Path $Root $Subdirectory) "dbgeng.dll")
}

function Invoke-NamedTest {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Test
    )
    & $Test
    Write-Host "[PASS] $Name" -ForegroundColor Green
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("windbg-mcp-rs-installer-tests-" + [Guid]::NewGuid().ToString("N"))
$templatePath = (Resolve-Path -LiteralPath (Join-Path $script:TestScriptDir "..\windbg_mcp_rs_GalleryManifest.xml")).Path
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    Invoke-NamedTest "architecture table and PE machines" {
        Assert-Equal $ArchitectureTable.Count 3 "architecture table count"
        Assert-Equal @($ArchitectureTable.Name | Select-Object -Unique).Count 3 "architecture names are unique"
        Assert-Equal @($ArchitectureTable.RustTarget | Select-Object -Unique).Count 3 "Rust targets are unique"
        Assert-Equal @($ArchitectureTable.StoreDllName | Select-Object -Unique).Count 3 "Store DLL names are unique"
        Assert-Equal (Get-ArchitectureByName -Name "x86").PeMachine ([uint16]0x014C) "x86 PE machine"
        Assert-Equal (Get-ArchitectureByName -Name "x64").PeMachine ([uint16]0x8664) "x64 PE machine"
        Assert-Equal (Get-ArchitectureByName -Name "arm64").PeMachine ([uint16]0xAA64) "ARM64 PE machine"

        foreach ($architecture in $ArchitectureTable) {
            $pePath = Join-Path $testRoot "pe\$($architecture.Name).dll"
            New-TestPe -Path $pePath -Machine $architecture.PeMachine
            Assert-Equal (Get-PeMachine -Path $pePath) $architecture.PeMachine "$($architecture.Name) PE parsing"
        }
        $unknownPe = Join-Path $testRoot "pe\unknown.dll"
        New-TestPe -Path $unknownPe -Machine ([uint16]0x0200)
        Assert-Throws -Action { Get-PeMachine -Path $unknownPe } -MessagePattern "Unsupported PE machine"
    }

    Invoke-NamedTest "flat and matrix local DLL discovery" {
        $flatRoot = Join-Path $testRoot "local-flat"
        New-TestPe -Path (Join-Path $flatRoot "windbg_mcp_rs.dll") -Machine (Get-ArchitectureByName "x86").PeMachine
        $flat = Resolve-LocalDlls -LocalPath $flatRoot
        Assert-Equal $flat.Count 1 "flat discovery result count"
        Assert-True $flat.ContainsKey("x86") "flat x86 DLL is keyed by PE machine"

        $matrixRoot = Join-Path $testRoot "local-matrix"
        foreach ($architecture in $ArchitectureTable) {
            New-TestPe -Path (Join-Path $matrixRoot (Join-Path $architecture.RustTarget "release\windbg_mcp_rs.dll")) -Machine $architecture.PeMachine
        }
        $matrix = Resolve-LocalDlls -LocalPath $matrixRoot
        Assert-Equal $matrix.Count 3 "matrix discovery result count"

        $mismatchRoot = Join-Path $testRoot "local-mismatch"
        $x86 = Get-ArchitectureByName "x86"
        $x64 = Get-ArchitectureByName "x64"
        New-TestPe -Path (Join-Path $mismatchRoot (Join-Path $x86.RustTarget "release\windbg_mcp_rs.dll")) -Machine $x64.PeMachine
        Assert-Throws -Action { Resolve-LocalDlls -LocalPath $mismatchRoot } -MessagePattern "architecture mismatch"

        $duplicateRoot = Join-Path $testRoot "local-duplicate"
        New-TestPe -Path (Join-Path $duplicateRoot "windbg_mcp_rs.dll") -Machine $x86.PeMachine
        New-TestPe -Path (Join-Path $duplicateRoot (Join-Path $x86.RustTarget "release\windbg_mcp_rs.dll")) -Machine $x86.PeMachine
        Assert-Throws -Action { Resolve-LocalDlls -LocalPath $duplicateRoot } -MessagePattern "Multiple DLLs"
    }

    Invoke-NamedTest "Appx-first and WindowsApps fallback discovery" {
        $oldAppx = Join-Path $testRoot "appx-old"
        $newAppx = Join-Path $testRoot "appx-new"
        foreach ($architecture in $ArchitectureTable) {
            New-EngineFixture -Root $oldAppx -Subdirectory $architecture.StorePackageDirectory
            New-EngineFixture -Root $newAppx -Subdirectory $architecture.StorePackageDirectory
        }
        $windowsApps = Join-Path $testRoot "WindowsApps"
        $fallbackPackage = Join-Path $windowsApps "Microsoft.WinDbg_2.0.0.0_x64__8wekyb3d8bbwe"
        foreach ($architecture in $ArchitectureTable) {
            New-EngineFixture -Root $fallbackPackage -Subdirectory $architecture.StorePackageDirectory
        }

        $appxRoots = @(Get-StorePackageRoots -AppxPackages @(
            [pscustomobject]@{ InstallLocation = $oldAppx; Version = [version]"1.9.0.0" },
            [pscustomobject]@{ InstallLocation = $newAppx; Version = [version]"1.10.0.0" }
        ) -WindowsAppsRoot $windowsApps)
        Assert-Equal $appxRoots.Count 2 "both usable Appx roots returned"
        Assert-Equal $appxRoots[0].Path (Resolve-Path $newAppx).Path "newest Appx package sorts first"
        Assert-True ($appxRoots.Path -notcontains $fallbackPackage) "WindowsApps fallback is skipped when Appx succeeds"

        $fallbackRoots = @(Get-StorePackageRoots -AppxPackages @() -WindowsAppsRoot $windowsApps)
        Assert-Equal $fallbackRoots.Count 1 "WindowsApps fallback package count"
        Assert-Equal $fallbackRoots[0].Path $fallbackPackage "WindowsApps fallback package"

        $emptyWindowsApps = Join-Path $testRoot "EmptyWindowsApps"
        New-Item -ItemType Directory -Path $emptyWindowsApps | Out-Null
        $localDbg = Join-Path $testRoot "DBG"
        New-Item -ItemType Directory -Path $localDbg | Out-Null
        Assert-Equal @(Get-StorePackageRoots -AppxPackages @() -WindowsAppsRoot $emptyWindowsApps).Count 0 "LOCALAPPDATA DBG is not package evidence"
    }

    Invoke-NamedTest "SDK and Store architecture mapping" {
        $sdkRoot = Join-Path $testRoot "sdk"
        $storePackage = Join-Path $testRoot "store-package"
        foreach ($architecture in $ArchitectureTable) {
            New-EngineFixture -Root $sdkRoot -Subdirectory $architecture.Name
            New-EngineFixture -Root $storePackage -Subdirectory $architecture.StorePackageDirectory
        }
        $storeBase = Join-Path $testRoot "mapped-store-base"
        $installations = @(Find-WinDbgInstallations -SdkRoots @($sdkRoot) -StorePackageRoots @([pscustomobject]@{ Path = $storePackage }) -StoreBasePath $storeBase)
        Assert-Equal $installations.Count 6 "SDK and Store installation count"
        Assert-Equal @($installations | Where-Object Type -eq "SDK").Count 3 "SDK architecture count"
        Assert-Equal @($installations | Where-Object Type -eq "Store").Count 3 "Store architecture count"
        Assert-Equal @($installations.Architecture.Name | Select-Object -Unique).Count 3 "mapped architecture count"
    }

    Invoke-NamedTest "unique Store DLL destinations and manifest entries" {
        $storeBase = Join-Path $testRoot "store-paths"
        $paths = @($ArchitectureTable | ForEach-Object { Get-StoreDllPath -BasePath $storeBase -Architecture $_ })
        Assert-Equal @($paths | Select-Object -Unique).Count 3 "Store destination paths are unique"
        Assert-True ($paths -contains (Join-Path $storeBase "EngineExtensions32\windbg_mcp_rs_x86.dll")) "x86 Store path"
        Assert-True ($paths -contains (Join-Path $storeBase "EngineExtensions\windbg_mcp_rs_x64.dll")) "x64 Store path"
        Assert-True ($paths -contains (Join-Path $storeBase "EngineExtensions\windbg_mcp_rs_arm64.dll")) "ARM64 Store path"

        $entries = @($ArchitectureTable | ForEach-Object {
            [pscustomobject]@{ Architecture = $_; ModulePath = Get-StoreDllPath -BasePath $storeBase -Architecture $_ }
        })
        $manifestText = New-StoreGalleryManifest -TemplatePath $templatePath -StoreEntries $entries
        [xml]$manifestXml = $manifestText
        $files = @($manifestXml.SelectNodes("//BinaryComponent/Files/File"))
        Assert-Equal $files.Count 3 "generated manifest File count"
        Assert-Equal (@($files.Architecture | Sort-Object) -join ",") "amd64,arm64,x86" "generated manifest architecture set"
        foreach ($file in $files) {
            Assert-Equal $file.FilePathKind "Absolute" "Store manifest path kind"
            Assert-True ([IO.Path]::IsPathRooted($file.Module)) "Store manifest module is absolute"
        }
        Assert-True (-not $manifestText.Contains('Architecture="Any"')) "generated Store manifest has no Any placeholder"
        Assert-True ([IO.File]::ReadAllText($templatePath).Contains('Architecture="Any"')) "checked-in template remains architecture neutral"

        $badTemplate = Join-Path $testRoot "bad-template.xml"
        [IO.File]::WriteAllText($badTemplate, "<ExtensionPackages />")
        Assert-Throws -Action { New-StoreGalleryManifest -TemplatePath $badTemplate -StoreEntries $entries } -MessagePattern "exactly one"
    }

    Invoke-NamedTest "Store transaction, failure preservation, and DryRun" {
        $sourceRoot = Join-Path $testRoot "store-sources"
        $pending = @($ArchitectureTable | ForEach-Object {
            $source = Join-Path $sourceRoot "$($_.Name).dll"
            New-TestPe -Path $source -Machine $_.PeMachine
            [pscustomobject]@{ Architecture = $_; SourceDll = $source }
        })

        $dryRunBase = Join-Path $testRoot "dry-run-store"
        $dryRunResult = Invoke-StoreManifestTransaction -BasePath $dryRunBase -PendingEntries $pending -TemplatePath $templatePath -DryRun
        Assert-Equal $dryRunResult.Validated 3 "DryRun validated Store architecture count"
        Assert-Equal $dryRunResult.Installed 0 "DryRun installed count"
        Assert-True (-not (Test-Path -LiteralPath $dryRunBase)) "DryRun creates no Store directories"

        $storeBase = Join-Path $testRoot "transaction-store"
        $success = Invoke-StoreManifestTransaction -BasePath $storeBase -PendingEntries $pending -TemplatePath $templatePath
        Assert-Equal $success.Installed 3 "successful Store transaction install count"
        Assert-Equal $success.Failed 0 "successful Store transaction failure count"
        Assert-True $success.Published "successful Store manifest publication"
        $manifestPath = Join-Path $storeBase "ExtRepository\windbg-mcp-rs\manifest.1.xml"
        $configPath = Join-Path $storeBase "ExtRepository\windbg-mcp-rs\config.xml"
        $versionPath = Join-Path $storeBase "ExtRepository\windbg-mcp-rs\ManifestVersion.txt"
        [xml]$null = [IO.File]::ReadAllText($manifestPath)
        [xml]$null = [IO.File]::ReadAllText($configPath)
        Assert-True (Test-Path -LiteralPath $versionPath -PathType Leaf) "ManifestVersion is published"
        foreach ($architecture in $ArchitectureTable) {
            $installedDll = Get-StoreDllPath -BasePath $storeBase -Architecture $architecture
            Assert-Equal (Get-PeMachine -Path $installedDll) $architecture.PeMachine "$($architecture.Name) installed Store PE"
        }

        $oldPayload = "old-manifest-payload"
        [IO.File]::WriteAllText($manifestPath, $oldPayload)
        $failure = Invoke-StoreManifestTransaction -BasePath $storeBase -PendingEntries $pending -TemplatePath $templatePath -BeforeManifestCommit { param($path) throw "injected manifest commit failure" }
        Assert-Equal $failure.Installed 0 "failed publication installed count"
        Assert-Equal $failure.Failed 3 "failed publication failure count"
        Assert-True (-not $failure.Published) "failed publication result"
        Assert-Equal ([IO.File]::ReadAllText($manifestPath)) $oldPayload "failed publication preserves old manifest"
        Assert-True (-not (Test-Path -LiteralPath "$manifestPath.tmp")) "failed publication removes manifest temp"

        $partialBase = Join-Path $testRoot "partial-store"
        $partialPending = @($pending)
        $partialPending[0] = [pscustomobject]@{ Architecture = $ArchitectureTable[0]; SourceDll = (Join-Path $testRoot "missing-x86.dll") }
        $partial = Invoke-StoreManifestTransaction -BasePath $partialBase -PendingEntries $partialPending -TemplatePath $templatePath
        Assert-Equal $partial.Installed 2 "valid Store entries still publish"
        Assert-Equal $partial.Failed 1 "missing Store source counted once"
        [xml]$partialManifest = [IO.File]::ReadAllText((Join-Path $partialBase "ExtRepository\windbg-mcp-rs\manifest.1.xml"))
        Assert-Equal @($partialManifest.SelectNodes("//BinaryComponent/Files/File")).Count 2 "failed copy is excluded from manifest"
    }

    Invoke-NamedTest "release DryRun uses validated release assets without installation writes" {
        $architecture = Get-ArchitectureByName "x64"
        $sourceDll = Join-Path $testRoot "release-dry-run\windbg_mcp_rs.dll"
        New-TestPe -Path $sourceDll -Machine $architecture.PeMachine
        $destination = Join-Path $testRoot "release-dry-run-sdk"
        $script:ReleaseDryRunInstallation = [pscustomobject]@{
            Path = $destination
            Architecture = $architecture
            Label = "SDK Debuggers (x64 fixture)"
            Type = "SDK"
            PackageRoot = $null
        }
        $script:ReleaseDryRunDll = $sourceDll
        $script:ReleaseDryRunManifest = $templatePath
        $script:ReleaseDryRunResolverCalled = $false
        $originalFindInstallations = ${function:Find-WinDbgInstallations}
        $originalResolveReleaseDlls = ${function:Resolve-ReleaseDlls}
        try {
            Set-Item -Path Function:Find-WinDbgInstallations -Value {
                return @($script:ReleaseDryRunInstallation)
            }
            Set-Item -Path Function:Resolve-ReleaseDlls -Value {
                param([object[]]$Architectures, [string]$Version)

                if ($Architectures.Count -ne 1 -or $Architectures[0].Name -ne "x64") {
                    throw "unexpected required architecture set"
                }
                $script:ReleaseDryRunResolverCalled = $true
                return @{
                    x64 = [pscustomobject]@{
                        Architecture = $Architectures[0]
                        Dll = $script:ReleaseDryRunDll
                        Manifest = $script:ReleaseDryRunManifest
                    }
                }
            }

            $result = Invoke-WindbgMcpInstall -DryRun
            Assert-True $script:ReleaseDryRunResolverCalled "release resolver is used by DryRun"
            Assert-Equal $result.Validated 1 "release DryRun validation count"
            Assert-Equal $result.Installed 0 "release DryRun installation count"
            Assert-Equal $result.Failed 0 "release DryRun failure count"
            Assert-True (-not (Test-Path -LiteralPath $destination)) "release DryRun creates no SDK destination"
        }
        finally {
            Set-Item -Path Function:Find-WinDbgInstallations -Value $originalFindInstallations
            Set-Item -Path Function:Resolve-ReleaseDlls -Value $originalResolveReleaseDlls
            Remove-Variable -Scope Script -Name ReleaseDryRunInstallation, ReleaseDryRunDll, ReleaseDryRunManifest, ReleaseDryRunResolverCalled -ErrorAction SilentlyContinue
        }
    }

    Invoke-NamedTest "installer failure exit semantics" {
        Assert-Equal (Get-InstallerExitCode -Result ([pscustomobject]@{ Failed = 0 })) 0 "zero failures exit successfully"
        Assert-Equal (Get-InstallerExitCode -Result ([pscustomobject]@{ Failed = 1 })) 1 "any failure exits unsuccessfully"
    }

    if ($BuildRoot) {
        Invoke-NamedTest "real release artifact PE machines" {
            $resolvedBuildRoot = (Resolve-Path -LiteralPath $BuildRoot -ErrorAction Stop).Path
            foreach ($architecture in $ArchitectureTable) {
                $dll = Join-Path $resolvedBuildRoot (Join-Path $architecture.RustTarget "release\windbg_mcp_rs.dll")
                Assert-True (Test-Path -LiteralPath $dll -PathType Leaf) "release DLL exists for $($architecture.RustTarget)"
                Assert-Equal (Get-PeMachine -Path $dll) $architecture.PeMachine "release DLL PE machine for $($architecture.Name)"
            }
        }
    }

    Write-Host "Installer validation passed." -ForegroundColor Green
    exit 0
}
catch {
    Write-Error $_
    exit 1
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# Stage A source. One bounded test per separately coordinated manual dispatch.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Package = 'PC-Stability-Guard-0.1.2-pkg.1'
$ArchiveHash = 'a6a7a8a698819c0d0cde2e36dfe86e2afd256db26668315f616cec533c384310'
$ManifestHash = 'a8c49a5263555397f6ce06ce1aef3748c7149da1ad5db3d7e55d59e0ad98aba1'
$ScriptHash = '30e6e5dfe10d0bc790799c20be449464555e63cf2ba2f4f339a818500baa7107'
$ExeHash = '31fe10b4ed82a2f960af0ef9931f46a4b84ff286f8b6ffd9dee098cf4f10f17f'
$Clock = [Diagnostics.Stopwatch]::StartNew()
$Cases = [ordered]@{}
foreach ($name in @('context','parse','archive','stage','installed','isolated-import','status','baseline','normal','post-normal','quarantine')) {
    $Cases[$name] = 'UNEXECUTED'
}
$Current = 'context'; $First = $null; $CleanupErrors = @(); $NormalStarted = $false
$Processes = New-Object 'System.Collections.Generic.List[PcsgSmoke.OwnedCommand]'
$Sequence = 0; $Trusted = $false; $PreservedRoot = $null; $EvidenceReady = $false
$Evidence = $null; $Root = $null; $Manifest = $null; $BeforeQuarantine = $null
$FinalSnapshotCaptured = $false

function Require([bool]$Value,[string]$Reason) { if (-not $Value) { throw $Reason } }
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Safe-Path([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    Require ($full -match '^[A-Za-z]:\\' -and $full -notmatch '[\x00-\x1f<>"|?*]') 'ABSOLUTE_LOCAL_PATH_REQUIRED'
    $cursor = [IO.Path]::GetPathRoot($full)
    foreach ($part in $full.Substring($cursor.Length).Split('\')) {
        if (-not $part) { continue }
        Require ($part -ne '.' -and $part -ne '..' -and $part -notmatch '[. :]+$|:') 'AMBIGUOUS_PATH'
        $cursor = [IO.Path]::Combine($cursor,$part)
        Require (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'REPARSE_REFUSED'
    }
    return $full
}
function Write-Receipt([string]$Name,$Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 15))
    Require ($bytes.Length -le 1048576) 'RECEIPT_BOUND'
    $f = [IO.File]::Open((Join-Path $Evidence $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $f.Write($bytes,0,$bytes.Length) } finally { $f.Dispose() }
}
function Read-JSON([string]$Path) {
    [void](Safe-Path $Path)
    Require ((Get-Item -LiteralPath $Path).Length -le 1048576) 'JSON_BOUND'
    [IO.File]::ReadAllText($Path) | ConvertFrom-Json
}
function Begin-Case([string]$Name) {
    $script:Current = $Name
    Require ($Clock.Elapsed.TotalSeconds -lt 300) 'ACTIVE_PHASE_DEADLINE'
    $Cases[$Name] = 'STARTED'
    Write-Receipt ($Name+'-begin.json') @{case=$Name;elapsed=$Clock.Elapsed.TotalSeconds;utc=[DateTime]::UtcNow.ToString('o')}
}
function Pass-Case { $Cases[$Current] = 'PASS' }
function Quote([string]$Value) {
    Require ($Value -notmatch '["\r\n]' -and -not $Value.EndsWith('\')) 'ARGUMENT_NOT_QUOTABLE'
    return '"'+$Value+'"'
}
function Failure-Details($Record) {
    if ($null -eq $Record) { return $null }
    $chain=@(); $exception=$Record.Exception
    for ($depth=0; $null -ne $exception -and $depth -lt 8; $depth++) {
        $row=@{type=$exception.GetType().FullName;message=$exception.Message}
        if ($exception -is [PcsgSmoke.NativeFailure]) {
            $row.operation=$exception.Operation; $row.pid=$exception.Pid; $row.winerror=$exception.Winerror
        }
        foreach ($key in @('owned_job_cleanup','owned_tree_empty_confirmed','owned_wrapper_exit_confirmed','owned_root_fallback_attempted')) {
            if ($exception.Data.Contains($key)) { $row[$key]=$exception.Data[$key] }
        }
        $chain+=$row; $exception=$exception.InnerException
    }
    return $chain
}
function Run-Process([string]$Label,[string]$Executable,[string]$Arguments,[int]$Seconds) {
    Require ($Seconds -ge 1 -and $Seconds -le 45) 'SUBPROCESS_DEADLINE_REQUIRED'
    Require ($Clock.Elapsed.TotalSeconds -lt 300) 'OVERALL_DEADLINE'
    $script:Sequence++
    $prefix = '{0:D2}-{1}' -f $script:Sequence,$Label
    $stdout = Join-Path $Evidence ($prefix+'-stdout.txt'); $stderr = Join-Path $Evidence ($prefix+'-stderr.txt')
    $p = $null; $problem = $null; $code = $null; $timedOut = $false
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $launchMilliseconds=[int][Math]::Min($Seconds*1000,[Math]::Max(0,(300-$Clock.Elapsed.TotalSeconds)*1000))
        $p = [PcsgSmoke.OwnedCommand]::Start($Executable,$Arguments,$Repo,$stdout,$stderr,$launchMilliseconds)
        $Processes.Add($p)
        while (-not $p.WaitForExit(100)) {
            foreach ($file in @($stdout,$stderr)) {
                if ([IO.File]::Exists($file)) { Require ((Get-Item -LiteralPath $file).Length -le 65536) 'CONTROL_OUTPUT_BOUND' }
            }
            if ($timer.Elapsed.TotalSeconds -ge $Seconds -or $Clock.Elapsed.TotalSeconds -ge 300) {
                $timedOut = $true; throw ('SUBPROCESS_DEADLINE: '+$Label)
            }
        }
        $code = $p.ExitCode
        foreach ($file in @($stdout,$stderr)) { Require ((Get-Item -LiteralPath $file).Length -le 65536) 'CONTROL_OUTPUT_BOUND' }
        Require ($code -eq 0) ('SUBPROCESS_NONZERO: '+$Label+' exit='+$code)
        # A successful wrapper exit alone never establishes descendant exit.
        Require ($p.ConfirmEmpty(3000)) 'OWNED_DESCENDANTS_REMAIN_AFTER_WRAPPER_EXIT'
        if ($timer.Elapsed.TotalSeconds -ge $Seconds -or $Clock.Elapsed.TotalSeconds -ge 300) {
            $timedOut = $true; throw ('SUBPROCESS_DEADLINE: '+$Label)
        }
    } catch {
        $problem = $_
        if ($timer.Elapsed.TotalSeconds -ge $Seconds -or $Clock.Elapsed.TotalSeconds -ge 300) { $timedOut=$true }
        # Stop the owned tree BEFORE receipt I/O or any grace wait. This covers
        # preflight with no runtime.json, all future wrapper admission, controller,
        # and nested workload/watchdog jobs. It does not depend on guard stop.
        if ($null -ne $p) {
            try { Require ($p.TerminateAndConfirm(3000)) 'OWNED_TREE_EXIT_UNCONFIRMED' }
            catch { $script:CleanupErrors += $_.Exception.Message }
        }
    }
    finally {
        if ($null -ne $p) {
            $p.Dispose()
            foreach ($errorText in $p.CleanupErrors) { $script:CleanupErrors += $errorText }
            if ($null -eq $problem -and $p.CleanupErrors.Count -gt 0) {
                $problem = [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('OWNED_HANDLE_CLEANUP_FAILED'),'OwnedCleanup',[Management.Automation.ErrorCategory]::CloseError,$Label)
            }
        }
        try { Write-Receipt ($prefix+'-result.json') @{label=$Label;pid=$(if($null -ne $p){$p.Id}else{$null});exit_code=$code;timeout=$timedOut;elapsed=$timer.Elapsed.TotalSeconds;failure=(Failure-Details $problem);owned_tree=$p} }
        catch { if ($null -eq $problem) { $problem = $_ } }
    }
    if ($null -ne $problem) { throw $problem }
    return @{stdout=$stdout;stderr=$stderr;exit_code=$code}
}
function Package-Call([string]$Action,[int]$Seconds) {
    $arguments = '-NoLogo -NoProfile -NonInteractive -File '+(Quote $Entry)+' -Action '+$Action
    if ($Action -in @('InspectArchive','Stage')) {
        $arguments += ' -ZipPath '+(Quote $Zip)+' -ArchiveSHA256 '+$ArchiveHash
    }
    if ($Action -ne 'InspectArchive') { $arguments += ' -Root '+(Quote $Root)+' -ManifestSHA256 '+$ManifestHash }
    if ($Action -in @('Stage','Status','Baseline','Normal','Quarantine')) { $arguments += ' -OwnerApproved' }
    if ($Action -eq 'Quarantine') { $arguments += ' -OwnerConfirmedStopped' }
    Run-Process $Action $PSExe $arguments $Seconds
}
function Frozen([string]$Base) {
    [void](Safe-Path $Base)
    Require ((Hash (Join-Path $Base 'PACKAGE-MANIFEST.json')) -eq $ManifestHash) 'MANIFEST_CHANGED'
    $count=0; $vendor=0
    foreach ($item in $Manifest.files.PSObject.Properties) {
        Require ($item.Name -cmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -and $item.Name.Split('/') -notcontains '..') 'MANIFEST_PATH'
        $path = Safe-Path (Join-Path $Base $item.Name.Replace('/','\'))
        $file = Get-Item -LiteralPath $path
        Require (-not $file.PSIsContainer -and $file.Length -eq $item.Value.bytes -and (Hash $path) -eq $item.Value.sha256) ('FROZEN_MISMATCH: '+$item.Name)
        $count++; if ($item.Name.StartsWith('runtime/')) { $vendor++ }
    }
    Require ($count -eq 85 -and $vendor -eq 34) 'FROZEN_INVENTORY_COUNT'
    $cache = Get-Item -LiteralPath (Safe-Path (Join-Path $Base 'app\__pycache__'))
    Require (-not $cache.PSIsContainer -and $cache.Length -eq 0) 'CACHE_SENTINEL_CHANGED'
    Require ((Hash (Join-Path $Base 'runtime\python.exe')) -eq $ExeHash) 'RUNTIME_EXE_CHANGED'
    return @{immutable_files=86;vendor_files=34;cache_sentinel_bytes=0;manifest_sha256=$ManifestHash}
}
function Action-Receipt([string]$Action) {
    $folder = Safe-Path (Join-Path $Root 'local-evidence')
    $found = @(); $count=0
    foreach ($dir in [IO.Directory]::EnumerateDirectories($folder)) {
        $count++; Require ($count -le 8) 'RECEIPT_DIRECTORY_BOUND'
        [void](Safe-Path $dir)
        $intent = Read-JSON (Join-Path $dir 'intent.json')
        if ($intent.action -eq $Action) { $found += $dir }
    }
    Require ($found.Count -eq 1) ('EXACT_ONE_ACTION_RECEIPT: '+$Action)
    return $found[0]
}
function Mutable-Snapshot([string]$Base,[string]$Label) {
    # Exact known mutable roots only. Never follow links, enumerate runtime/vendor,
    # research data, host paths, or a partially staged untrusted tree.
    $inventory = @(); [long]$total=0; $count=0
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($rel in @('app\state','app\scratch','local-evidence')) {
        $path=Join-Path $Base $rel
        if ([IO.Directory]::Exists($path)) { $pending.Push($path) }
    }
    while ($pending.Count) {
        Require ($Clock.Elapsed.TotalSeconds -lt 360) 'EVIDENCE_DEADLINE'
        $dir = Safe-Path $pending.Pop()
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($dir)) {
            $count++; Require ($count -le 96) 'EVIDENCE_ENTRY_BOUND'
            [void](Safe-Path $path)
            $relative=$path.Substring($Base.Length+1)
            Require ($relative.Split('\').Count -le 8) 'EVIDENCE_DEPTH_BOUND'
            $item=Get-Item -LiteralPath $path
            if ($item.PSIsContainer) { $pending.Push($path); continue }
            Require ($item.Length -le 262144 -and $relative -notmatch '(?i)\.(exe|dll|py|pyc|pyo|pyd|ps1|cmd|bat)$') 'MUTABLE_EVIDENCE_BOUND'
            $total += $item.Length; Require ($total -le 8388608) 'EVIDENCE_TOTAL_BOUND'
            $target=$Label+('-mutable-{0:D3}.bin' -f $inventory.Count)
            $copy=Join-Path $Evidence $target
            [IO.File]::Copy($path,$copy,$false)
            $captured=(Get-Item -LiteralPath $copy).Length
            Require ($captured -eq $item.Length -and $captured -le 262144) 'MUTABLE_CHANGED_DURING_CAPTURE'
            $inventory += @{path=$relative;bytes=$captured;sha256=(Hash $copy);evidence_file=$target}
        }
    }
    Write-Receipt ($Label+'-mutable-inventory.json') @{files=$inventory;bytes=$total;root=$Base}
    return (($inventory | Sort-Object { $_.path } | ForEach-Object { $_.path+'|'+$_.sha256+'|'+$_.bytes }) -join "`n")
}

try {
    Require ($env:GITHUB_ACTIONS -ceq 'true' -and $env:RUNNER_ENVIRONMENT -ceq 'github-hosted' -and $env:RUNNER_OS -ceq 'Windows' -and $env:RUNNER_ARCH -ceq 'X64') 'GITHUB_HOSTED_WINDOWS_X64_ONLY'
    Require ($env:GITHUB_REPOSITORY -ceq 'sterlingstreamsllc/windows-stability-guardrail-validation' -and $env:PCSG_REPOSITORY_ID -ceq '1428899604' -and $env:PCSG_PRIVATE -ceq 'false') 'PUBLIC_APPROVED_REPOSITORY_ONLY'
    Require ($env:GITHUB_EVENT_NAME -ceq 'workflow_dispatch' -and $env:GITHUB_RUN_ATTEMPT -ceq '1') 'ONE_MANUAL_ATTEMPT_ONLY'
    Require ($env:GITHUB_REF -ceq 'refs/heads/main' -and $env:PCSG_APPROVAL -ceq 'PACKAGE-ONLY-ONE-RUN') 'APPROVED_BRANCH_AND_CONFIRMATION_REQUIRED'
    Require ($env:PCSG_REVIEWED_COMMIT -cmatch '^[0-9a-f]{40}$' -and $env:GITHUB_SHA -ceq $env:PCSG_REVIEWED_COMMIT) 'REVIEWED_COMMIT_REQUIRED'
    Require ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'WINDOWS_POWERSHELL_5_1_REQUIRED'
    $Repo = Safe-Path $env:GITHUB_WORKSPACE
    $Evidence = Safe-Path (Join-Path $env:RUNNER_TEMP ('pcsg-package-'+$env:GITHUB_RUN_ID+'-'+$env:GITHUB_RUN_ATTEMPT))
    $EvidenceReady = $true
    Write-Receipt 'owner-abi.json' @{layout=[PcsgSmoke.OwnedCommand]::VerifyAbi();source_sha256=(Hash (Join-Path $Repo 'ci\OwnedCommand.cs'));native_behavior='PROSPECTIVE; containment receipts required for every command'}
    $PSExe = Safe-Path (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')
    $Entry = Safe-Path (Join-Path $Repo 'packaging\pkg.1\Package.ps1')
    $Zip = Safe-Path (Join-Path $Repo ('package-candidates\0.1.2-pkg.1\'+$Package+'.zip'))
    $Root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) $Package
    $PreservedRoot = $Root
    Write-Receipt 'context.json' @{provider='github-hosted';repo=$env:GITHUB_REPOSITORY;repository_id=$env:PCSG_REPOSITORY_ID;commit=$env:GITHUB_SHA;ref=$env:GITHUB_REF;run_id=$env:GITHUB_RUN_ID;attempt=$env:GITHUB_RUN_ATTEMPT;image=$env:ImageVersion;image_os=$env:ImageOS;os=[Environment]::OSVersion.VersionString;processors=[Environment]::ProcessorCount;powershell=$PSVersionTable.PSVersion.ToString();policies=@(Get-ExecutionPolicy -List | Select-Object Scope,ExecutionPolicy);root=$Root;production='DISABLED';expected_capacity='Public standard Windows documented16GB total; actual unchanged baseline decides'}
    Require ((Get-Item -LiteralPath $Zip).Length -eq 11600050 -and (Hash $Zip) -eq $ArchiveHash) 'FROZEN_ARCHIVE_REQUIRED'
    Require ((Hash $Entry) -eq $ScriptHash) 'EXTERNAL_UNCHANGED_PACKAGE_SCRIPT_REQUIRED'
    Require (-not (Test-Path -LiteralPath $Root)) 'FRESH_FIXED_ROOT_REQUIRED'
    Pass-Case
    Begin-Case 'parse'
    foreach ($path in @($PSCommandPath,$Entry)) {
        $tokens=$null; $errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
        Write-Receipt (([IO.Path]::GetFileName($path))+'-parse.json') @{file=$path;sha256=(Hash $path);tokens=@($tokens).Count;ast=$ast.GetType().FullName;errors=@($errors | ForEach-Object { $_.ToString() })}
        Require (@($errors).Count -eq 0) 'NATIVE_POWERSHELL_PARSE_FAILED'
    }
    Pass-Case
    Begin-Case 'archive'; [void](Package-Call 'InspectArchive' 30); Pass-Case
    Begin-Case 'stage'; [void](Package-Call 'Stage' 45); Pass-Case
    Begin-Case 'installed'
    Require ((Hash (Join-Path $Root 'PACKAGE-MANIFEST.json')) -eq $ManifestHash) 'STAGED_MANIFEST_HASH'
    $Manifest=Read-JSON (Join-Path $Root 'PACKAGE-MANIFEST.json')
    Require ($Manifest.version -eq '0.1.2-pkg.1' -and $Manifest.production -eq 'DISABLED') 'PACKAGE_IDENTITY'
    Write-Receipt 'frozen-before.json' (Frozen $Root)
    [void](Package-Call 'InspectInstalled' 20); $Trusted=$true; Pass-Case
    Begin-Case 'isolated-import'
    $probe=Run-Process 'probe' (Join-Path $Root 'runtime\python.exe') ('-I '+(Quote (Join-Path $Repo 'ci\package-runtime-probe.py'))+' '+(Quote $Root)) 8
    $probeData=Read-JSON $probe.stdout
    Require ($probeData.status -eq 'PROBE_COMPLETE' -and $probeData.workload_admissions -eq 0 -and $probeData.child_processes_started -eq 0) 'PROBE_RESULT'
    Write-Receipt 'frozen-after-probe.json' (Frozen $Root); Pass-Case
    Begin-Case 'status'; [void](Package-Call 'Status' 15)
    $status=Read-JSON (Join-Path (Action-Receipt 'Status') 'status-stdout.txt')
    Require ($status.state -eq 'NOT_STARTED' -and $status.production -eq 'DISABLED') 'INITIAL_STATUS_REQUIRED'
    Pass-Case
    Begin-Case 'baseline'; [void](Package-Call 'Baseline' 15)
    $baseline=Read-JSON (Join-Path (Action-Receipt 'Baseline') 'baseline-stdout.txt')
    Require ($baseline.available_bytes -ge 8589934592 -and $baseline.commit_headroom_bytes -ge 6442450944) 'INSUFFICIENT_HEADROOM_NO_THRESHOLD_CHANGE'
    Pass-Case
    Begin-Case 'normal'; $NormalStarted=$true
    [void](Package-Call 'Normal' 10) # Owner intervention clock begins at command start.
    $r=Read-JSON (Join-Path $Root 'app\state\runtime.json')
    Require ($r.state -eq 'CLOSED' -and $r.final_accounting.active -eq 0 -and $r.final_accounting.total -eq 1 -and $r.watchdog_exit_confirmed -eq $true -and @($r.cleanup_errors).Count -eq 0 -and $r.process_observation -eq 'COMPLETE') 'NORMAL_CLEAN_EXIT_REQUIRED'
    Require ($null -eq $r.first_error) 'NORMAL_FIRST_ERROR_PRESENT'
    [void](Action-Receipt 'Normal'); Pass-Case
    Begin-Case 'post-normal'
    Write-Receipt 'frozen-after-normal.json' (Frozen $Root)
    [void](Package-Call 'InspectInstalled' 20)
    Require ([IO.File]::Exists((Join-Path $Root 'local-evidence\ONE-NORMAL-ATTEMPT.json'))) 'SINGLE_ATTEMPT_MARKER_REQUIRED'
    Pass-Case
    Begin-Case 'quarantine'
    foreach ($p in $Processes) { Require ($p.WrapperExitConfirmed -and $p.TreeEmptyConfirmed -and $p.CleanupErrors.Count -eq 0) 'OWNED_HELPER_TREE_EXIT_UNCONFIRMED' }
    $BeforeQuarantine=Mutable-Snapshot $Root 'pre-quarantine'
    $quarantine=Package-Call 'Quarantine' 20
    $line=[IO.File]::ReadAllText($quarantine.stdout).Trim()
    $prefix='PRESERVED_WITHOUT_DELETION; CONTENTS_NOT_VALIDATED: '
    Require ($line.StartsWith($prefix)) 'QUARANTINE_RECEIPT_REQUIRED'
    $destination=$line.Substring($prefix.Length)
    Require ($destination -cmatch ('^'+[regex]::Escape($Root)+'\.quarantine-[0-9TZ]+-[0-9a-f]{32}$')) 'QUARANTINE_PATH_REQUIRED'
    $PreservedRoot=Safe-Path $destination
    Require (-not (Test-Path -LiteralPath $Root)) 'ORIGINAL_ROOT_REMAINS'
    Write-Receipt 'frozen-after-quarantine.json' (Frozen $PreservedRoot)
    $after=Mutable-Snapshot $PreservedRoot 'post-quarantine'
    Require ($after -ceq $BeforeQuarantine) 'QUARANTINE_MUTABLE_BYTES_CHANGED'
    $FinalSnapshotCaptured=$true
    Pass-Case
} catch {
    $First=@{case=$Current;message=$_.Exception.Message;detail=$_.ToString();elapsed=$Clock.Elapsed.TotalSeconds}
    $Cases[$Current]='FAIL'
} finally {
    # Each command has already terminated/confirmed its owned tree, or retained
    # an explicit failure. No guard-stop/NO_IDENTIFIED_JOB fallback or admission
    # grace period is used. Dispose is idempotent and never resumes a process.
    foreach ($p in $Processes) {
        try {
            $p.Dispose()
            Require ($p.TreeEmptyConfirmed) 'OWNED_TREE_EXIT_UNCONFIRMED'
        } catch { $CleanupErrors += $_.Exception.Message }
    }
    if ($EvidenceReady) {
        try {
            if ($Trusted -and -not $FinalSnapshotCaptured -and [IO.Directory]::Exists($PreservedRoot)) {
                [void](Mutable-Snapshot $PreservedRoot 'final')
            }
        } catch { $CleanupErrors += ('EVIDENCE_PARTIAL: '+$_.Exception.Message) }
        try {
            $marker=$false; $runtimeState=$false
            if ($Trusted -and [IO.Directory]::Exists($PreservedRoot)) {
                $marker=[IO.File]::Exists((Join-Path $PreservedRoot 'local-evidence\ONE-NORMAL-ATTEMPT.json'))
                $runtimeState=[IO.File]::Exists((Join-Path $PreservedRoot 'app\state\runtime.json'))
            }
            Write-Receipt 'final.json' @{status=$(if($null -eq $First -and $CleanupErrors.Count -eq 0){'PASS'}else{'FAIL'});first_failure=$First;cleanup_errors=$CleanupErrors;cases=$Cases;normal_command_attempted=$NormalStarted;normal_marker_observed=$marker;runtime_json_observed=$runtimeState;runtime_cleanup_validation=$(if($Cases['normal'] -eq 'PASS'){'PASS'}else{'UNEXECUTED_OR_UNCONFIRMED'});preserved_root=$PreservedRoot;elapsed=$Clock.Elapsed.TotalSeconds;unexecuted_by_scope=@('active emergency exercise','hang','concurrency','negative reparse','partial rollback','21-case engine rerun');production='DISABLED'}
        } catch { $CleanupErrors += $_.Exception.Message; Write-Error -ErrorAction Continue ('FINAL_EVIDENCE_FAILED: '+$_.Exception.Message) }
    }
}
if ($null -ne $First) { Write-Error -ErrorAction Continue ($First | ConvertTo-Json -Depth 5) }
if ($null -ne $First -or $CleanupErrors.Count -gt 0) { exit 1 }
exit 0

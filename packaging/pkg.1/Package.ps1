# Source-reviewed packaging candidate. Windows behavior UNEXECUTED.
# No network, PATH changes, installation of dependencies, policy bypass, or elevation.
[CmdletBinding()]
param(
    [ValidateSet('Info','InspectArchive','Stage','InspectInstalled','Baseline','Status','Normal','Stop','Quarantine','PreservePartial')]
    [string]$Action = 'Info',
    [string]$ZipPath,
    [string]$ArchiveSHA256,
    [string]$Root,
    [string]$ManifestSHA256,
    [switch]$OwnerApproved,
    [switch]$OwnerConfirmedStopped
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PackageName = 'PC-Stability-Guard-0.1.2-pkg.1'
$PackageVersion = '0.1.2-pkg.1'
$ExpectedRuntimeArchive = '97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297'

function Require([bool]$Condition, [string]$Reason) {
    if (-not $Condition) { throw $Reason }
}
function SHA256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function No-Reparse([string]$Path, [bool]$MissingLeaf = $false) {
    $full = [IO.Path]::GetFullPath($Path)
    Require ($full -match '^[A-Za-z]:\\' -and $full -notmatch '[\x00-\x1f<>"|?*]' -and
        $full.Substring(2) -notmatch ':') 'LOCAL_ABSOLUTE_PATH_REQUIRED'
    Require ($full -notmatch '(?i)(^C:\\(AI|work)(\\|$)|(^|\\)(J-GRAM|USEFM)(\\|$))') 'PROHIBITED_PATH'
    $cursor = [IO.Path]::GetPathRoot($full)
    foreach ($part in $full.Substring($cursor.Length).Split('\')) {
        if (-not $part) { continue }
        Require ($part -notmatch '[. ]$') 'AMBIGUOUS_PATH_COMPONENT'
        $cursor = [IO.Path]::Combine($cursor,$part)
        try {
            $attributes = [IO.File]::GetAttributes($cursor)
            Require (($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'REPARSE_POINT_REFUSED'
        } catch {
            $cause = $_.Exception
            while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
            Require ($MissingLeaf -and $cursor -eq $full -and
                $cause -is [IO.FileNotFoundException]) 'PATH_ATTRIBUTES_FAILED_OR_COMPONENT_MISSING'
            # File.Exists also returns false for some dangling links/errors.
            # A missing leaf is accepted only after literal attributes fail with
            # FileNotFound and its checked parent has no such directory entry.
            $parent = [IO.Path]::GetDirectoryName($cursor)
            $leaf = [IO.Path]::GetFileName($cursor)
            $count = 0
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($parent,$leaf,[IO.SearchOption]::TopDirectoryOnly)) {
                $count++; Require ($count -le 4096) 'MISSING_LEAF_PARENT_BOUND'
                Require (-not [string]::Equals([IO.Path]::GetFileName($entry),$leaf,[StringComparison]::OrdinalIgnoreCase)) 'DANGLING_OR_UNREADABLE_ENTRY_REFUSED'
            }
        }
    }
    return $full
}
function Install-Root([string]$Value, [bool]$MissingLeaf = $false) {
    $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $expected = [IO.Path]::Combine($base,$PackageName)
    Require (-not [string]::IsNullOrWhiteSpace($Value)) 'EXPLICIT_INSTALL_ROOT_REQUIRED'
    $full = [IO.Path]::GetFullPath($Value)
    Require ([string]::Equals($full,$expected,[StringComparison]::OrdinalIgnoreCase)) 'ONLY_FRESH_FIXED_PER_USER_ROOT_ALLOWED'
    [void](No-Reparse $full $MissingLeaf)
    return $full
}
function Relative-Name([string]$Name) {
    Require ($Name.Length -le 200 -and $Name -cmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$') 'UNSAFE_ARCHIVE_NAME'
    foreach ($part in $Name.Split('/')) {
        Require ($part -ne '.' -and $part -ne '..' -and $part -ne '.git' -and
            $part -notmatch '[. ]$' -and $part -notmatch '(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') 'UNSAFE_WINDOWS_COMPONENT'
    }
}
function Write-New([string]$Path,[byte[]]$Bytes) {
    [void](No-Reparse ([IO.Path]::GetDirectoryName($Path)))
    Require (-not [IO.File]::Exists($Path) -and -not [IO.Directory]::Exists($Path)) 'NO_OVERWRITE'
    $stream = [IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
}
function Write-JSON([string]$Path,$Value) {
    $text = $Value | ConvertTo-Json -Depth 12
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    Require ($bytes.Length -le 32768) 'RECEIPT_SIZE_LIMIT'
    Write-New $Path $bytes
}
function New-Directory([string]$Path) {
    [void](No-Reparse ([IO.Path]::GetDirectoryName($Path)))
    Require (-not [IO.Directory]::Exists($Path) -and -not [IO.File]::Exists($Path)) 'DIRECTORY_ALREADY_EXISTS'
    [void](New-Item -ItemType Directory -Path $Path -ErrorAction Stop)
    [void](No-Reparse $Path)
}
function Read-JSON([string]$Path) {
    [void](No-Reparse $Path)
    Require ((Get-Item -LiteralPath $Path).Length -le 1048576) 'JSON_SIZE_LIMIT'
    return [IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) | ConvertFrom-Json
}
function Manifest-Map($Manifest) {
    Require ($Manifest.version -eq $PackageVersion -and $Manifest.production -eq 'DISABLED') 'UNREVIEWED_PACKAGE'
    Require ($Manifest.runtime.archive_sha256 -eq $ExpectedRuntimeArchive) 'UNREVIEWED_RUNTIME'
    $map = @{}
    foreach ($property in $Manifest.files.PSObject.Properties) {
        Relative-Name $property.Name
        Require (-not $map.ContainsKey($property.Name)) 'CASE_COLLISION'
        Require ($property.Value.sha256 -cmatch '^[0-9a-f]{64}$' -and
            $property.Value.bytes -ge 0 -and $property.Value.bytes -le 33554432) 'INVALID_FILE_RECEIPT'
        $map[$property.Name] = $property.Value
    }
    Require ($map.Count -ge 40 -and $map.Count -le 512) 'PACKAGE_FILE_COUNT'
    return $map
}
function Inspect-Archive {
    Require ($ArchiveSHA256 -match '^[0-9a-fA-F]{64}$') 'TRUSTED_ARCHIVE_SHA256_REQUIRED'
    $path = No-Reparse $ZipPath
    Require ((Get-Item -LiteralPath $path).Length -le 33554432) 'ARCHIVE_SIZE_LIMIT'
    Require ((SHA256 $path) -eq $ArchiveSHA256.ToLowerInvariant()) 'ARCHIVE_HASH_MISMATCH'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($path)
    try {
        $entries = @{}; [long]$total = 0
        foreach ($entry in $archive.Entries) {
            Relative-Name $entry.FullName
            Require (-not $entries.ContainsKey($entry.FullName)) 'ARCHIVE_CASE_COLLISION'
            Require (($entry.ExternalAttributes -band 1024) -eq 0 -and
                ($entry.ExternalAttributes -band 16) -eq 0 -and
                (($entry.ExternalAttributes -shr 16) -band 61440) -in @(0,32768)) 'ARCHIVE_NONREGULAR_REFUSED'
            Require ($entry.Length -ge 0 -and $entry.Length -le 33554432) 'ARCHIVE_ENTRY_SIZE'
            $total += $entry.Length
            Require ($total -le 134217728 -and $entries.Count -lt 512) 'ARCHIVE_TOTAL_LIMIT'
            $entries[$entry.FullName] = $entry
        }
        foreach ($name in $entries.Keys) {
            $parts = $name.Split('/')
            for ($i=1; $i -lt $parts.Length; $i++) {
                Require (-not $entries.ContainsKey(($parts[0..($i-1)] -join '/'))) 'ARCHIVE_FILE_DIRECTORY_COLLISION'
            }
        }
        Require ($entries.ContainsKey('PACKAGE-MANIFEST.json')) 'MANIFEST_MISSING'
        Require ($entries['PACKAGE-MANIFEST.json'].Length -le 1048576) 'MANIFEST_SIZE'
        $reader = [IO.StreamReader]::new($entries['PACKAGE-MANIFEST.json'].Open(),[Text.Encoding]::UTF8)
        try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        $map = Manifest-Map $manifest
        Require ($entries.Count -eq $map.Count+1) 'ARCHIVE_EXTRA_OR_MISSING_FILES'
        foreach ($name in $map.Keys) {
            Require ($entries.ContainsKey($name)) 'PAYLOAD_FILE_MISSING'
            $entry = $entries[$name]
            Require ($entry.Length -eq $map[$name].bytes) 'PAYLOAD_SIZE_MISMATCH'
            $stream = $entry.Open(); $hash = [Security.Cryptography.SHA256]::Create()
            try { $actual = [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
            finally { $hash.Dispose(); $stream.Dispose() }
            Require ($actual -eq $map[$name].sha256) 'PAYLOAD_HASH_MISMATCH'
        }
        if ($Action -eq 'Stage') {
            Require $OwnerApproved.IsPresent 'EXPLICIT_OWNER_STAGING_APPROVAL_REQUIRED'
            $destination = Install-Root $Root $true
            New-Directory $destination
            # No bulk ExtractToDirectory, overwrite, links or inherited archive paths.
            # Partial failure remains in place for review; no cleanup deletes evidence.
            foreach ($entry in $archive.Entries) {
                $target = [IO.Path]::Combine($destination,$entry.FullName.Replace('/','\'))
                $parent = [IO.Path]::GetDirectoryName($target)
                $parts = $parent.Substring($destination.Length).TrimStart('\').Split('\')
                $cursor = $destination
                foreach ($part in $parts) {
                    if (-not $part) { continue }
                    $cursor = [IO.Path]::Combine($cursor,$part)
                    if (-not [IO.Directory]::Exists($cursor)) { New-Directory $cursor }
                    [void](No-Reparse $cursor)
                }
                $inputStream = $entry.Open()
                try {
                    $memory = New-Object IO.MemoryStream
                    try { $inputStream.CopyTo($memory); Write-New $target ($memory.ToArray()) }
                    finally { $memory.Dispose() }
                } finally { $inputStream.Dispose() }
            }
            $script:ManifestSHA256 = SHA256 ([IO.Path]::Combine($destination,'PACKAGE-MANIFEST.json'))
            [void](Verify-Installed $destination)
            Write-Output ('STAGED_ONLY; NO_RUNTIME_EXECUTED; manifest_sha256='+$script:ManifestSHA256)
        } else { Write-Output 'ARCHIVE_HASH_AND_ALL_FILES_VERIFIED; NO_FILES_STAGED; NO_RUNTIME_EXECUTED' }
    } finally { $archive.Dispose() }
}
function Files-Below([string]$Base, $AllowedDirectories = $null) {
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Base); $count = 0
    while ($pending.Count) {
        $directory = $pending.Pop()
        [void](No-Reparse $directory)
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $count++; Require ($count -le 1024) 'TREE_ENTRY_LIMIT'
            [void](No-Reparse $path)
            $attributes = [IO.File]::GetAttributes($path)
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                Require ($path.Substring($Base.Length).Split('\').Count -le 8) 'TREE_DEPTH_LIMIT'
                if ($null -ne $AllowedDirectories) {
                    $relative = $path.Substring($Base.Length+1).Replace('\','/')
                    $mutableDirectory = $relative -in @('app/state','app/scratch','local-evidence') -or
                        $relative -match '^local-evidence/[0-9TZ-]+-[0-9a-f]{32}(/(before|after)(/(state|scratch))?)?$'
                    Require ($AllowedDirectories.ContainsKey($relative) -or $mutableDirectory) 'UNREVIEWED_EXTRA_DIRECTORY'
                }
                $pending.Push($path)
            } else { Write-Output $path }
        }
    }
}
function Verify-Installed([string]$Base, [bool]$StopOnly = $false) {
    [void](Install-Root $Base)
    Require ($ManifestSHA256 -match '^[0-9a-fA-F]{64}$') 'TRUSTED_MANIFEST_SHA256_REQUIRED'
    $manifestPath = [IO.Path]::Combine($Base,'PACKAGE-MANIFEST.json')
    [void](No-Reparse $manifestPath)
    Require ((SHA256 $manifestPath) -eq $ManifestSHA256.ToLowerInvariant()) 'MANIFEST_HASH_MISMATCH'
    $map = Manifest-Map (Read-JSON $manifestPath)
    $sentinel = [IO.Path]::Combine($Base,'app','__pycache__')
    [void](No-Reparse $sentinel)
    Require ([IO.File]::Exists($sentinel) -and (Get-Item -LiteralPath $sentinel).Length -eq 0) 'IMMUTABLE_CACHE_SENTINEL_REQUIRED'
    if ($StopOnly) {
        # No mutable traversal, receipts or logs may block emergency termination.
        # Verify every runtime byte and the complete app import directory first.
        $critical = @('app/guard.py','app/native.py','app/pe_fixture.py','app/config.json','app/__pycache__')
        foreach ($name in $map.Keys) {
            if ($name.StartsWith('runtime/') -or $name -in $critical) {
                $path = [IO.Path]::Combine($Base,$name.Replace('/','\'))
                [void](No-Reparse $path)
                Require ([IO.File]::Exists($path) -and (Get-Item -LiteralPath $path).Length -eq $map[$name].bytes -and
                    (SHA256 $path) -eq $map[$name].sha256) 'STOP_CODE_INTEGRITY_FAILED'
            }
        }
        foreach ($path in Files-Below ([IO.Path]::Combine($Base,'runtime')) @{}) {
            Require ($map.ContainsKey($path.Substring($Base.Length+1).Replace('\','/'))) 'EXTRA_RUNTIME_CODE_REFUSED'
        }
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries([IO.Path]::Combine($Base,'app'))) {
            [void](No-Reparse $path)
            $name = [IO.Path]::GetFileName($path)
            # Preserved historical source directories are not imported by stop.
            $knownDirectory = $name -in @('state','scratch','.github','review-history')
            Require ($map.ContainsKey('app/'+$name) -or ($knownDirectory -and [IO.Directory]::Exists($path))) 'EXTRA_APP_IMPORT_PATH_REFUSED'
        }
        $stateDirectory = [IO.Path]::Combine($Base,'app','state')
        [void](No-Reparse $stateDirectory $true)
        Require (-not [IO.File]::Exists($stateDirectory)) 'STATE_MUST_BE_DIRECTORY_OR_ABSENT'
        if ([IO.Directory]::Exists($stateDirectory)) {
            # Exact bounded leaf checks, no enumeration/hash/size scan of state.
            # emergency reads runtime/breaker, creates breaker atomically, and
            # appends/rotates operator logs. Include watchdog-trip for inspection.
            foreach ($leaf in @('runtime.json','breaker.json','watchdog-trip.json','operator.jsonl','operator.jsonl.1','operator.jsonl.2')) {
                [void](No-Reparse ([IO.Path]::Combine($stateDirectory,$leaf)) $true)
            }
        }
        return $map
    }
    $directories = @{}
    foreach ($name in $map.Keys) {
        $parts = $name.Split('/')
        for ($i=1; $i -lt $parts.Length; $i++) { $directories[($parts[0..($i-1)] -join '/')] = $true }
    }
    $seen = @{}; [long]$mutableBytes = 0
    foreach ($path in Files-Below $Base $directories) {
        $relative = $path.Substring($Base.Length+1).Replace('\','/')
        $length = (Get-Item -LiteralPath $path).Length
        if ($relative -eq 'PACKAGE-MANIFEST.json') { continue }
        if ($map.ContainsKey($relative)) {
            Require ($length -eq $map[$relative].bytes -and (SHA256 $path) -eq $map[$relative].sha256) 'FROZEN_FILE_CHANGED'
            $seen[$relative] = $true
        } else {
            $state = $relative -match '^app/state/((runtime|breaker|watchdog-trip|admission)\.json(\.[a-z0-9_]{8}\.new)?|(controller|watchdog|operator)\.jsonl(\.[12])?)$'
            $scratch = $relative -eq 'app/scratch/fixture.json'
            $receipt = $relative -match '^local-evidence/(ONE-NORMAL-ATTEMPT\.json|[0-9TZ-]+-[0-9a-f]{32}/[A-Za-z0-9_./-]+)$'
            Require ($state -or $scratch -or $receipt) 'UNREVIEWED_EXTRA_FILE'
            Require ($relative -notmatch '(?i)\.(py|pyc|pyo|pyd|dll|exe|ps1|cmd|bat)$') 'EXTRA_EXECUTABLE_REFUSED'
            Require ($length -le 262144) 'MUTABLE_FILE_LIMIT'
            $mutableBytes += $length; Require ($mutableBytes -le 33554432) 'MUTABLE_TOTAL_LIMIT'
            # Mutable observations are never imported or trusted as code.
        }
    }
    Require ($seen.Count -eq $map.Count) 'FROZEN_FILE_MISSING'
    return $map
}
function New-Receipt([string]$Base,[string]$Label) {
    $evidence = [IO.Path]::Combine($Base,'local-evidence')
    if (-not [IO.Directory]::Exists($evidence)) { New-Directory $evidence }
    $id = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N')
    $folder = [IO.Path]::Combine($evidence,$id)
    New-Directory $folder
    Write-JSON ([IO.Path]::Combine($folder,'intent.json')) @{action=$Label;utc=[DateTime]::UtcNow.ToString('o');package=$PackageVersion;manifest_sha256=$ManifestSHA256}
    return $folder
}
function Snapshot([string]$Base,[string]$Receipt,[string]$Stage) {
    $target = [IO.Path]::Combine($Receipt,$Stage); New-Directory $target
    [long]$total = 0; $count = 0
    foreach ($name in @('state','scratch')) {
        $source = [IO.Path]::Combine($Base,'app',$name)
        if (-not [IO.Directory]::Exists($source)) { continue }
        [void](No-Reparse $source)
        $out = [IO.Path]::Combine($target,$name); New-Directory $out
        foreach ($file in [IO.Directory]::EnumerateFiles($source)) {
            [void](No-Reparse $file)
            $length = (Get-Item -LiteralPath $file).Length
            $total += $length; $count++
            Require ($length -le 262144 -and $total -le 8388608 -and $count -le 64) 'SNAPSHOT_BOUND'
            Write-New ([IO.Path]::Combine($out,[IO.Path]::GetFileName($file))) ([IO.File]::ReadAllBytes($file))
        }
    }
}
function Runtime-Call([string]$Base,[string]$Receipt,[string]$Command,[int]$Seconds) {
    $python = [IO.Path]::Combine($Base,'runtime','python.exe')
    $app = [IO.Path]::Combine($Base,'app')
    $stdout = [IO.Path]::Combine($Receipt,$Command+'-stdout.txt')
    $stderr = [IO.Path]::Combine($Receipt,$Command+'-stderr.txt')
    Require (-not [IO.File]::Exists($stdout) -and -not [IO.File]::Exists($stderr)) 'OUTPUT_ALREADY_EXISTS'
    # Immutable regular-file app/__pycache__ also protects unchanged -I children.
    $arguments = '-I -B '
    if ($Command -eq 'baseline') {
        $arguments += '"'+[IO.Path]::Combine($Base,'Baseline.py')+'"'
    } else {
        $arguments += '"'+[IO.Path]::Combine($app,'guard.py')+'" '+$(if ($Command -eq 'normal') { 'run normal' } else { $Command })
    }
    $process = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $app -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $timedOut = $false
    try {
        $null = $process.Handle # retain the exact process before waiting
        if (-not $process.WaitForExit($Seconds*1000)) {
            $timedOut = $true
            # The exact controller we created is terminated. Its job-owner closure
            # is crash cleanup, never an unrelated PID/name kill or a new workload.
            $process.Kill()
            Require ($process.WaitForExit(3000)) 'OWNED_PROCESS_EXIT_UNCONFIRMED'
        }
        Require ((Get-Item -LiteralPath $stdout).Length -le 32768 -and (Get-Item -LiteralPath $stderr).Length -le 32768) 'CONTROL_OUTPUT_LIMIT'
        $result = @{operation=$Command;pid=$process.Id;exit_code=$process.ExitCode;timeout=$timedOut;utc=[DateTime]::UtcNow.ToString('o')}
        Write-JSON ([IO.Path]::Combine($Receipt,$Command+'-result.json')) $result
        Require (-not $timedOut) 'RUNTIME_DEADLINE_FAILED_NO_RETRY'
        Require ($process.ExitCode -eq 0) 'RUNTIME_COMMAND_FAILED_NO_RETRY'
        return [IO.File]::ReadAllText($stdout)
    } finally { $process.Dispose() }
}

function Stop-Now([string]$Base) {
    [void](Verify-Installed $Base $true)
    # Critical stop precedes any snapshot, receipt creation or mutable validation.
    # Console output remains available even when evidence storage is broken/full.
    $python = [IO.Path]::Combine($Base,'runtime','python.exe')
    $arguments = '-I -B "'+[IO.Path]::Combine($Base,'app','guard.py')+'" stop'
    $process = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory ([IO.Path]::Combine($Base,'app')) -PassThru -NoNewWindow
    $result = @{action='Stop';status='FAIL';utc=[DateTime]::UtcNow.ToString('o')}
    $stopFailure = $null
    try {
        $null = $process.Handle
        $result.pid = $process.Id
        if (-not $process.WaitForExit(8000)) {
            $result.timeout = $true
            $process.Kill()
            Require ($process.WaitForExit(3000)) 'STOP_HELPER_EXIT_UNCONFIRMED'
            throw 'STOP_DEADLINE_FAILED; retain console output; no retry or reset'
        }
        $result.exit_code = $process.ExitCode
        Require ($process.ExitCode -eq 0) 'STOP_FAILED; retain console output; no retry or reset'
        $result.status = 'COMMAND_COMPLETED'
    } catch {
        $stopFailure = $_
        $result.reason = $_.Exception.Message
    } finally {
        $process.Dispose()
        try {
            $receipt = New-Receipt $Base 'Stop'
            Write-JSON ([IO.Path]::Combine($receipt,'stop-result.json')) $result
            Snapshot $Base $receipt 'after'
            Write-Output ('STOP_RECEIPTS: '+$receipt)
        } catch {
            Write-Warning ('STOP_PARTIAL_EVIDENCE: '+$_.Exception.Message+'; retain console output.')
            if ($null -eq $stopFailure) { $stopFailure = $_ }
        }
    }
    if ($null -ne $stopFailure) { throw $stopFailure }
}

function Preserve-Root([string]$Base) {
    Require $OwnerApproved.IsPresent 'EXPLICIT_PRESERVATION_APPROVAL_REQUIRED'
    Require $OwnerConfirmedStopped.IsPresent 'OWNER_MUST_CONFIRM_NO_RUNNING_COMMANDS'
    [void](Install-Root $Base)
    Require ([IO.Directory]::Exists($Base)) 'ORDINARY_DIRECTORY_REQUIRED'
    $destination = $Base+'.quarantine-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N')
    [void](No-Reparse $destination $true)
    Require (-not [IO.Directory]::Exists($destination) -and -not [IO.File]::Exists($destination)) 'QUARANTINE_TARGET_EXISTS'
    # Directory.Move preserves the complete tree without traversing or following
    # any nested links. No payload execution, validation, deletion or repair.
    [IO.Directory]::Move($Base,$destination)
    Write-Output ('PRESERVED_WITHOUT_DELETION; CONTENTS_NOT_VALIDATED: '+$destination)
}

if ($Action -eq 'Info') {
    Write-Output '0.1.2-pkg.1: preparation candidate; production DISABLED; packaged Windows/local behavior UNEXECUTED.'
    Write-Output 'Read LOCAL-VALIDATION-PLAN.md and OPERATOR-CARD.txt. Default action makes no changes and starts no runtime.'
    exit 0
}
if ($Action -in @('InspectArchive','Stage')) { Inspect-Archive; exit 0 }
$Root = Install-Root $Root
if ($Action -eq 'PreservePartial') { Preserve-Root $Root; exit 0 }
if ($Action -eq 'Stop') {
    Require $OwnerApproved.IsPresent 'EXPLICIT_ACTION_APPROVAL_REQUIRED'
    Stop-Now $Root
    exit 0
}
[void](Verify-Installed $Root)
if ($Action -eq 'InspectInstalled') { Write-Output 'FROZEN_HASHES_VERIFIED; MUTABLE_BYTES_NOT_TRUSTED_AS_CODE; NO_RUNTIME_EXECUTED'; exit 0 }
Require $OwnerApproved.IsPresent 'EXPLICIT_ACTION_APPROVAL_REQUIRED'
if ($Action -eq 'Quarantine') {
    Require $OwnerConfirmedStopped.IsPresent 'OWNER_MUST_CONFIRM_STOPPED'
    $state = [IO.Path]::Combine($Root,'app','state','runtime.json')
    if ([IO.File]::Exists($state)) {
        $r = Read-JSON $state
        Require ($r.state -in @('OPEN','CLOSED') -and $r.final_accounting.active -eq 0 -and $r.watchdog_exit_confirmed -eq $true) 'QUARANTINE_REFUSED_UNCONFIRMED_EXIT'
        foreach ($name in @('controller_pid','root_pid','watchdog_pid')) {
            if ($r.PSObject.Properties.Name -contains $name) {
                $live = Get-Process -Id $r.$name -ErrorAction SilentlyContinue
                Require ($null -eq $live) 'RECORDED_PID_EXISTS_REFUSE_NO_KILL'
            }
        }
    }
    Preserve-Root $Root
    exit 0
}
Require ([IO.File]::Exists([IO.Path]::Combine([Environment]::SystemDirectory,'ucrtbase.dll'))) 'HOST_UCRT_PREREQUISITE_MISSING_NO_INSTALL'
$receipt = New-Receipt $Root $Action
$primaryFailure = $null
try {
    Snapshot $Root $receipt 'before'
    if ($Action -eq 'Normal') {
        # This packaging candidate permits one attempt only, including failed preflight.
        $marker = [IO.Path]::Combine($Root,'local-evidence','ONE-NORMAL-ATTEMPT.json')
        Write-JSON $marker @{receipt=[IO.Path]::GetFileName($receipt);utc=[DateTime]::UtcNow.ToString('o');case='normal';retries=0}
        $baseline = (Runtime-Call $Root $receipt 'baseline' 8) | ConvertFrom-Json
        Require ($baseline.available_bytes -ge 8589934592 -and $baseline.commit_headroom_bytes -ge 6442450944) 'INSUFFICIENT_HEADROOM_NO_THRESHOLD_CHANGE'
        $state = [IO.Path]::Combine($Root,'app','state','runtime.json')
        Require (-not [IO.File]::Exists($state)) 'INITIAL_TRIAL_REQUIRES_FRESH_STATE_NO_RESET'
        [void](Runtime-Call $Root $receipt 'normal' 35)
        $r = Read-JSON $state
        Require ($r.state -eq 'CLOSED' -and $r.final_accounting.active -eq 0 -and
            $r.final_accounting.total -eq 1 -and $r.watchdog_exit_confirmed -eq $true -and
            @($r.cleanup_errors).Count -eq 0 -and $r.process_observation -eq 'COMPLETE') 'NORMAL_ACCEPTANCE_FAILED'
        Require ($r.limits_read_back -eq $true -and $r.limits.active_limit -eq 2 -and
            $r.limits.flags -eq 8972 -and $r.limits.job_memory -eq 268435456 -and
            $r.limits.process_memory -eq 201326592 -and $r.limits.job_user_time -eq 80000000 -and
            $r.limits.cpu_flags -eq 5 -and $r.limits.cpu_rate -eq 2000) 'WORKLOAD_LIMIT_READBACK_FAILED'
        Require ($r.watchdog_limits.active_limit -eq 1 -and $r.watchdog_limits.flags -eq 8972 -and
            $r.watchdog_limits.job_memory -eq 134217728 -and $r.watchdog_limits.process_memory -eq 100663296 -and
            $r.watchdog_limits.job_user_time -eq 80000000 -and $r.watchdog_limits.cpu_flags -eq 5 -and
            $r.watchdog_limits.cpu_rate -eq 500) 'WATCHDOG_LIMIT_READBACK_FAILED'
        $f = Read-JSON ([IO.Path]::Combine($Root,'app','scratch','fixture.json'))
        Require ($f.normal -eq $true) 'NORMAL_FIXTURE_RECEIPT_MISSING'
    } else {
        $controlOutput = Runtime-Call $Root $receipt ($Action.ToLowerInvariant()) 8
        Write-Output $controlOutput
        if ($Action -eq 'Baseline') {
            $baseline = $controlOutput | ConvertFrom-Json
            Require ($baseline.available_bytes -ge 8589934592 -and $baseline.commit_headroom_bytes -ge 6442450944) 'INSUFFICIENT_HEADROOM_NO_THRESHOLD_CHANGE'
        }
    }
} catch {
    $primaryFailure = $_
    try { Write-JSON ([IO.Path]::Combine($receipt,'failure.json')) @{status='FAIL';action=$Action;reason=$_.Exception.Message;retry='FORBIDDEN'} }
    catch { Write-Warning 'Primary failure retained in memory; failure receipt write also failed.' }
} finally {
    # Snapshot failure must not overwrite the primary operation failure receipt.
    try { Snapshot $Root $receipt 'after' }
    catch {
        $snapshotFailure = $_
        try { Write-JSON ([IO.Path]::Combine($receipt,'snapshot-failure.json')) @{status='FAIL';reason=$snapshotFailure.Exception.Message} }
        catch { Write-Warning 'Snapshot failure receipt write failed; retain console output.' }
        if ($null -eq $primaryFailure) { $primaryFailure = $snapshotFailure }
    }
}
if ($null -ne $primaryFailure) {
    Write-Warning 'STOP ON FIRST ANOMALY. Use the separately prepared exact Stop command; preserve receipts. No reset or repeat.'
    throw $primaryFailure
}
[void](Verify-Installed $Root)
Write-JSON ([IO.Path]::Combine($receipt,'outcome.json')) @{status='COMMAND_COMPLETED';action=$Action;production='DISABLED'}
Write-Output ('RECEIPTS_PRESERVED: '+$receipt)

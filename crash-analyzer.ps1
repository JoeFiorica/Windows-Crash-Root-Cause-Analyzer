#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position=0)][string]$Command = 'help',
    [object]$Days = 7,
    [string]$StartTime,
    [string]$EndTime,
    [string]$IncidentTime,
    [string]$OutputFolder,
    [string]$InputFile,
    [string]$Format = 'Both',
    [object]$MaxEventsPerChannel = 2000,
    [object]$QueryTimeoutSeconds = 20,
    [switch]$Library,
    [switch]$Worker,
    [ValidateSet('System','Application','Microsoft-Windows-WindowsUpdateClient/Operational','Context')][string]$Channel,
    [string]$Start,[string]$End,
    [ValidateRange(1,10000)][int]$MaxEvents=2000,
    [string]$ResultPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


# Analyzer.Core.psm1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function ConvertFrom-JsonText([string]$Json) {
    # PowerShell 7.5+ otherwise coerces ISO strings to DateTime and loses offsets.
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        return ConvertFrom-Json -InputObject $Json -DateKind String
    }
    return ConvertFrom-Json -InputObject $Json
}

function Get-Value($Object, [string]$Name, $Default = $null) {
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
    } elseif ($null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function ConvertTo-Instant([string]$Value) {
    if ($Value -notmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$') {
        throw 'Timestamp must be ISO 8601 with an explicit UTC offset or Z.'
    }
    return [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-EventRules {
    @(
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-Power'; Ids=@(41); Kind='UnexpectedShutdown'},
        @{Channel='System'; Provider='EventLog'; Ids=@(6008); Kind='UnexpectedShutdown'},
        @{Channel='System'; Provider='USER32'; Ids=@(1074); Kind='PlannedRestart'},
        @{Channel='System'; Provider='Microsoft-Windows-WER-SystemErrorReporting'; Ids=@(1001); Kind='Bugcheck'},
        @{Channel='System'; Provider='BugCheck'; Ids=@(1001); Kind='Bugcheck'},
        @{Channel='Application'; Provider='Windows Error Reporting'; Ids=@(1001); Kind='WerReport'},
        @{Channel='Application'; Provider='Application Error'; Ids=@(1000); Kind='ApplicationFailure'},
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-General'; Ids=@(12); Kind='Boot'},
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-General'; Ids=@(13); Kind='Shutdown'},
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-General'; Ids=@(1); Kind='ClockChange'},
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-General'; Ids=@(22); Kind='TimeZoneChange'},
        @{Channel='System'; Provider='EventLog'; Ids=@(6005); Kind='LogStart'},
        @{Channel='System'; Provider='EventLog'; Ids=@(6006); Kind='LogStop'},
        @{Channel='System'; Provider='Microsoft-Windows-Eventlog'; Ids=@(104); Kind='LogCleared'},
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-Power'; Ids=@(42); Kind='Sleep'},
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-Power'; Ids=@(107); Kind='Resume'},
        @{Channel='System'; Provider='Microsoft-Windows-Power-Troubleshooter'; Ids=@(1); Kind='Resume'},
        @{Channel='System'; Provider='disk'; Ids=@(7,11,15,51,153,157); Kind='Storage'},
        @{Channel='System'; Provider='storahci'; Ids=@(129); Kind='Storage'},
        @{Channel='System'; Provider='stornvme'; Ids=@(129); Kind='Storage'},
        @{Channel='System'; Provider='iaStorA'; Ids=@(129); Kind='Storage'},
        @{Channel='System'; Provider='iaStorAC'; Ids=@(129); Kind='Storage'},
        @{Channel='System'; Provider='Microsoft-Windows-Ntfs'; Ids=@(55,98); Kind='Storage'},
        @{Channel='System'; Provider='Ntfs'; Ids=@(55,98); Kind='Storage'},
        @{Channel='System'; Provider='volmgr'; Ids=@(46,161); Kind='DumpFailure'},
        @{Channel='System'; Provider='Microsoft-Windows-WHEA-Logger'; Ids=@(1,17,18,19,20,46,47); Kind='Hardware'},
        @{Channel='System'; Provider='Microsoft-Windows-Kernel-PnP'; Ids=@(219); Kind='DriverService'},
        @{Channel='System'; Provider='Service Control Manager'; Ids=@(7000,7001,7009,7011,7023,7024,7031,7034); Kind='DriverService'},
        @{Channel='System'; Provider='Microsoft-Windows-WindowsUpdateClient'; Ids=@(19,20,21,43); Kind='Update'},
        @{Channel='Microsoft-Windows-WindowsUpdateClient/Operational'; Provider='Microsoft-Windows-WindowsUpdateClient'; Ids=@(25,31,41,42,43,44); Kind='Update'}
    )
}

function Get-EventKind([string]$Channel, [string]$Provider, [int]$Id) {
    foreach ($rule in (Get-EventRules)) {
        if ($Channel -eq $rule.Channel -and $Provider -eq $rule.Provider -and $Id -in $rule.Ids) { return $rule.Kind }
    }
    return 'Unmapped'
}

function Get-EventQueryXml([string]$Channel, [string]$Start, [string]$End) {
    # A separate Select per provider/ID group avoids one oversized XPath predicate.
    $selections = foreach ($rule in (Get-EventRules | Where-Object { $_.Channel -eq $Channel })) {
        $ids = ($rule.Ids | ForEach-Object { 'EventID=' + $_ }) -join ' or '
        $xpath = "*[System[Provider[@Name='$($rule.Provider)'] and ($ids) and TimeCreated[@SystemTime>='$Start' and @SystemTime<='$End']]]"
        '<Select Path="' + [Security.SecurityElement]::Escape($Channel) + '">' + [Security.SecurityElement]::Escape($xpath) + '</Select>'
    }
    '<QueryList><Query Id="0" Path="' + [Security.SecurityElement]::Escape($Channel) + '">' + ($selections -join '') + '</Query></QueryList>'
}

function ConvertTo-SafeEvent($Record) {
    $channel = [string](Get-Value $Record 'Channel')
    $provider = [string](Get-Value $Record 'Provider')
    $id = 0
    if (-not [int]::TryParse([string](Get-Value $Record 'Id'), [ref]$id)) { throw 'Invalid event ID.' }
    $kind = Get-EventKind $channel $provider $id
    if ($kind -eq 'Unmapped') { return $null }
    # Canonical provider/channel strings come from the rule table, never input casing.
    $rule = Get-EventRules | Where-Object { $_.Channel -eq $channel -and $_.Provider -eq $provider -and $id -in $_.Ids } | Select-Object -First 1
    $time = ConvertTo-Instant ([string](Get-Value $Record 'TimeCreated'))
    $rid = 0L
    if (-not [long]::TryParse([string](Get-Value $Record 'RecordId'), [ref]$rid) -or $rid -lt 0) { throw 'Invalid record ID.' }
    $version = 0
    if (-not [int]::TryParse([string](Get-Value $Record 'Version' 0), [ref]$version) -or $version -lt 0 -or $version -gt 255) { throw 'Invalid version.' }
    $level = 0
    if (-not [int]::TryParse([string](Get-Value $Record 'Level' 0), [ref]$level) -or $level -lt 0 -or $level -gt 5) { throw 'Invalid level.' }
    $data = [ordered]@{}
    $source = Get-Value $Record 'Data'
    foreach ($name in @('BugcheckCode','SleepInProgress','BootAppStatus','LongPowerButtonPressDetected','ErrorSource','ErrorType','Status','errorCode','TargetState','EffectiveState','BootMode','TimeDeltaInMs','OldBias','NewBias')) {
        $value = [string](Get-Value $source $name)
        if ($value -match '^(?:0[xX][0-9a-fA-F]{1,16}|-?\d{1,20}|true|false)$') { $data[$name] = $value }
    }
    foreach ($name in @('OldTime','NewTime','StartTime','StopTime','SleepTime','WakeTime')) {
        $value = [string](Get-Value $source $name)
        if ($value) { try { $data[$name] = (ConvertTo-Instant $value).ToString('o') } catch {} }
    }
    # WER's schema uses param1 for the bugcheck and param2 for a dump path.
    # Keep only the leading numeric stop code, never paths or free-form strings.
    if ($kind -eq 'Bugcheck') {
        $param = [string](Get-Value $source 'param1')
        if ($param -match '^\s*(0x[0-9a-fA-F]{1,8})(?:\s|\(|$)') { $data['StopCode'] = $Matches[1].ToLowerInvariant() }
        $stop = [string](Get-Value $source 'StopCode')
        if ($stop -match '^0x[0-9a-fA-F]{1,8}$') { $data['StopCode'] = $stop.ToLowerInvariant() }
    }
    if ($kind -eq 'WerReport') {
        $eventName = [string](Get-Value $source 'EventName')
        foreach ($known in @('BlueScreen','LiveKernelEvent','APPCRASH','AppHangB1')) {
            if ($eventName -ceq $known) { $data['EventName'] = $known }
        }
    }
    if ($kind -eq 'PlannedRestart') {
        $reason = [string](Get-Value $source 'param4' (Get-Value $source 'ReasonCode'))
        if ($reason -match '^0x[0-9a-fA-F]{1,8}$') { $data['ReasonCode'] = $reason.ToLowerInvariant() }
    }
    [pscustomobject][ordered]@{
        Channel=$rule.Channel; Provider=$rule.Provider; Id=$id; Version=$version; Level=$level
        RecordId=$rid; TimeCreated=$time.ToString('o'); TimeUtc=$time.UtcDateTime.ToString('o')
        Kind=$kind; Data=[pscustomobject]$data
    }
}

function ConvertFrom-EventXml([string]$Xml) {
    # XmlReader prohibits DTDs and external resolution even for offline inputs.
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create((New-Object IO.StringReader($Xml)), $settings)
    try { $doc = New-Object Xml.XmlDocument; $doc.XmlResolver = $null; $doc.Load($reader) } finally { $reader.Dispose() }
    $ns = New-Object Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    $system = $doc.SelectSingleNode('/e:Event/e:System', $ns)
    if ($null -eq $system) { throw 'Missing event System element.' }
    $data = @{}; $index = 0
    foreach ($node in $doc.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $name = $node.GetAttribute('Name'); if (-not $name) { $name = 'param' + (++$index) }
        $data[$name] = $node.InnerText
    }
    $getText = { param($name, $fallback) $node = $system.SelectSingleNode('e:' + $name, $ns); if ($node) { $node.InnerText } else { $fallback } }
    ConvertTo-SafeEvent ([pscustomobject]@{
        Channel=(& $getText 'Channel' ''); Provider=$system.SelectSingleNode('e:Provider',$ns).GetAttribute('Name')
        Id=(& $getText 'EventID' ''); Version=(& $getText 'Version' '0'); Level=(& $getText 'Level' '0')
        RecordId=(& $getText 'EventRecordID' ''); TimeCreated=$system.SelectSingleNode('e:TimeCreated',$ns).GetAttribute('SystemTime'); Data=$data
    })
}

function Get-SafeEvidence($InputObject) {
    if ((Get-Value $InputObject 'SchemaVersion') -ne '1.0') { throw 'Unsupported evidence file version. Use evidence.json saved by this tool.' }
    if ((Get-Value $InputObject 'DocumentType') -ne 'Evidence') { throw 'Input must be an evidence.json file saved by this tool, rather than a generated report.' }
    $eventProperty = $InputObject.PSObject.Properties['Events']
    if ($null -eq $eventProperty -or $eventProperty.Value -isnot [array]) { throw 'Input must include the event list from a complete evidence.json file.' }
    $start = ConvertTo-Instant ([string](Get-Value (Get-Value $InputObject 'Window') 'Start'))
    $end = ConvertTo-Instant ([string](Get-Value (Get-Value $InputObject 'Window') 'End'))
    if ($end -lt $start -or ($end - $start).TotalDays -gt 366) { throw 'Evidence window must span 0 to 366 days.' }
    $events = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}; $invalid = 0; $duplicates = 0; $unmapped = 0; $outside = 0
    $rawEvents = @(Get-Value $InputObject 'Events' @())
    if ($rawEvents.Count -gt 30000) { throw 'Evidence exceeds 30000 records.' }
    foreach ($record in $rawEvents) {
        try {
            $event = ConvertTo-SafeEvent $record
            if ($null -eq $event) { $unmapped++; continue }
            $at = ConvertTo-Instant $event.TimeCreated
            if ($at -lt $start -or $at -gt $end) { $outside++; continue }
            $key = '{0}|{1}|{2}|{3}|{4}' -f $event.Channel,$event.Provider,$event.RecordId,$event.Id,$event.TimeUtc
            if ($seen.ContainsKey($key)) { $duplicates++; continue }; $seen[$key] = $true
            $events.Add($event)
        } catch { $invalid++ }
    }
    $coverage = @()
    foreach ($channel in @('System','Application','Microsoft-Windows-WindowsUpdateClient/Operational')) {
        $item = @(Get-Value $InputObject 'Coverage' @()) | Where-Object { (Get-Value $_ 'Channel') -eq $channel } | Select-Object -First 1
        $status = [string](Get-Value $item 'Status' 'NotCollected')
        if ($status -notin @('Complete','Truncated','AccessDenied','Unavailable','Timeout','Error','NotCollected')) { $status = 'Error' }
        $oldest = $null
        try { $oldest = (ConvertTo-Instant ([string](Get-Value $item 'OldestAvailable'))).ToString('o') } catch {}
        $count = @($events | Where-Object { $_.Channel -eq $channel }).Count
        $coverage += [pscustomobject]@{Channel=$channel;Status=$status;Count=$count;OldestAvailable=$oldest}
    }
    $context = Get-Value $InputObject 'Context'
    $version = [string](Get-Value $context 'WindowsVersion' 'Unknown')
    if ($version -notmatch '^\d{1,2}\.\d{1,2}\.\d{1,6}(?:\.\d{1,6})?$') { $version = 'Unknown' }
    $arch = [string](Get-Value $context 'Architecture' 'Unknown')
    if ($arch -notin @('AMD64','ARM64','x86')) { $arch = 'Unknown' }
    $tz = 'Unknown'
    try { $tz = [TimeZoneInfo]::FindSystemTimeZoneById([string](Get-Value $context 'TimeZoneId')).Id } catch {}
    $dumpStatus = [string](Get-Value $InputObject 'DumpStatus' 'NotCollected')
    if ($dumpStatus -notin @('Found','NoneFound','AccessDenied','Truncated','Timeout','Error','NotCollected')) { $dumpStatus = 'Error' }
    $dumps = @()
    foreach ($dump in @(Get-Value $InputObject 'Dumps' @()) | Select-Object -First 256) {
        try {
            $size = 0L
            if (-not [long]::TryParse([string](Get-Value $dump 'SizeBytes'),[ref]$size) -or $size -lt 0) { continue }
            $dumps += [pscustomobject]@{Reference=('dump-{0:d3}' -f ($dumps.Count+1));LastWriteTime=(ConvertTo-Instant ([string](Get-Value $dump 'LastWriteTime'))).ToString('o');SizeBytes=$size}
        } catch {}
    }
    $collected = $null
    try { $collected = (ConvertTo-Instant ([string](Get-Value $InputObject 'CollectedAt'))).ToString('o') } catch {}
    $inputNotes = Get-Value $InputObject 'InputNotes'
    $notes = [ordered]@{Malformed=$invalid;Duplicates=$duplicates;Unmapped=$unmapped;OutsideWindow=$outside}
    foreach ($name in @('Malformed','Duplicates','Unmapped','OutsideWindow')) {
        $number = 0
        if ([int]::TryParse([string](Get-Value $inputNotes $name),[ref]$number) -and $number -ge 0 -and $number -le 30000) { $notes[$name] += $number }
    }
    [pscustomobject][ordered]@{
        SchemaVersion='1.0'; DocumentType='Evidence'; CollectedAt=$collected; Privacy='SanitizedAllowlist'
        Window=[pscustomobject]@{Start=$start.ToString('o');End=$end.ToString('o')}
        Context=[pscustomobject]@{WindowsVersion=$version;Architecture=$arch;TimeZoneId=$tz}
        Coverage=@($coverage); DumpStatus=$dumpStatus; Dumps=@($dumps)
        Events=@($events | Sort-Object TimeUtc,Channel,RecordId)
        InputNotes=[pscustomobject]$notes
    }
}

function New-Hypothesis([string]$Classification, [string]$Title, [string]$Confidence, [object[]]$Events, [string]$Explanation, [string]$NextTest) {
    [pscustomobject]@{Classification=$Classification;Title=$Title;Confidence=$Confidence;Evidence=@($Events | ForEach-Object { '{0}/{1}/{2}@{3}' -f $_.Channel,$_.Provider,$_.Id,$_.RecordId });Explanation=$Explanation;NextTest=$NextTest}
}

function Test-PositiveBugcheck($Event) {
    $code = [string](Get-Value $Event.Data 'BugcheckCode')
    $number = 0L
    if ($code -match '^0x[0-9a-fA-F]{1,8}$') { return [Convert]::ToInt64($code.Substring(2),16) -gt 0 }
    return ([long]::TryParse($code,[ref]$number) -and $number -gt 0 -and $number -le [uint32]::MaxValue)
}

function Get-IncidentReport($Evidence, [string]$IncidentTime = '') {
    $safe = Get-SafeEvidence $Evidence
    $events = @($safe.Events)
    # Parse each timestamp once for repeated context-window searches.
    $timelineIndex = @($events | ForEach-Object { [pscustomobject]@{Event=$_;Ticks=(ConvertTo-Instant $_.TimeCreated).UtcDateTime.Ticks} })
    $bootIndex = @($timelineIndex | Where-Object { $_.Event.Kind -eq 'Boot' })
    $contextTicks = [TimeSpan]::FromMinutes(15).Ticks
    $gaps = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $safe.Coverage) {
        if ($item.Status -ne 'Complete') { $gaps.Add($item.Channel + ': ' + $item.Status + '; absence of events is not evidence of absence.') }
        if ($item.OldestAvailable -and (ConvertTo-Instant $item.OldestAvailable) -gt (ConvertTo-Instant $safe.Window.Start)) { $gaps.Add($item.Channel + ': retained log starts after the requested window began.') }
    }
    if ($safe.InputNotes.Malformed) { $gaps.Add('Malformed records excluded: ' + $safe.InputNotes.Malformed) }
    if ($safe.InputNotes.Unmapped) { $gaps.Add('Unmapped provider/channel/ID records excluded: ' + $safe.InputNotes.Unmapped) }
    if ($safe.InputNotes.OutsideWindow) { $gaps.Add('Records outside the collection window excluded: ' + $safe.InputNotes.OutsideWindow) }
    if ($safe.DumpStatus -ne 'Found') { $gaps.Add('Minidump inventory: ' + $safe.DumpStatus + '. Missing metadata does not disprove a bugcheck.') }
    if (@($events | Where-Object { $_.Kind -eq 'ClockChange' }).Count) { $gaps.Add('Clock adjustment recorded. UTC sorting may differ from physical event order; compare same-channel record IDs. Proximity-based findings are weakened.') }
    if (@($events | Where-Object { $_.Kind -eq 'TimeZoneChange' }).Count) { $gaps.Add('Timezone bias change recorded. Live event XML timestamps are UTC; the collection timezone is current context and may differ from the incident timezone.') }
    if (@($events | Where-Object { $_.Kind -eq 'LogCleared' }).Count) { $gaps.Add('An event-log clear was recorded; coverage may be incomplete.') }
    # Same-channel record IDs are an independent ordering clue across backward clock changes.
    $previous = $null
    foreach ($event in @($events | Where-Object { $_.Channel -eq 'System' } | Sort-Object RecordId)) {
        if ($previous -and (ConvertTo-Instant $event.TimeCreated) -lt (ConvertTo-Instant $previous.TimeCreated)) { $gaps.Add('System record ID order conflicts with timestamp order (clock change, log reset, or imported records).'); break }
        $previous = $event
    }
    $anchors = @($events | Where-Object { $_.Kind -in @('UnexpectedShutdown','Bugcheck','PlannedRestart','Boot') })
    if ($IncidentTime) {
        $target = ConvertTo-Instant $IncidentTime
        if ($target -lt (ConvertTo-Instant $safe.Window.Start) -or $target -gt (ConvertTo-Instant $safe.Window.End)) { throw 'Incident time is outside the evidence window.' }
        $anchors = @([pscustomobject]@{TimeCreated=$target.ToString('o');Kind='RequestedIncident'})
    }
    $clusters = New-Object 'System.Collections.Generic.List[object]'
    foreach ($anchor in $anchors) {
        $at = ConvertTo-Instant $anchor.TimeCreated
        if ($clusters.Count -and [math]::Abs(($at - $clusters[$clusters.Count-1].At).TotalMinutes) -le 10) {
            $clusters[$clusters.Count-1].Anchors.Add($anchor)
        } else {
            $list = New-Object 'System.Collections.Generic.List[object]'; $list.Add($anchor)
            $clusters.Add([pscustomobject]@{At=$at;Anchors=$list})
        }
    }
    if ($clusters.Count -gt 200) { $gaps.Add('More than 200 recovery clusters; only the latest 200 are analyzed. The complete bounded event timeline is retained. Narrow the window for earlier incidents.') }
    $incidents = @()
    foreach ($cluster in @($clusters | Select-Object -Last 200)) {
        $at = $cluster.At
        $lowerTicks = $at.UtcDateTime.Ticks - $contextTicks
        $upperTicks = $at.UtcDateTime.Ticks + $contextTicks
        $near = @($timelineIndex | Where-Object { $_.Ticks -ge $lowerTicks -and $_.Ticks -le $upperTicks } | ForEach-Object { $_.Event })
        $unexpected = @($near | Where-Object { $_.Kind -eq 'UnexpectedShutdown' })
        $bug = @($near | Where-Object { $_.Kind -eq 'Bugcheck' -or ($_.Kind -eq 'WerReport' -and (Get-Value $_.Data 'EventName') -ceq 'BlueScreen') })
        $kpBug = @($unexpected | Where-Object { Test-PositiveBugcheck $_ })
        $planned = @($near | Where-Object { $_.Kind -eq 'PlannedRestart' })
        $boot = @($near | Where-Object { $_.Kind -eq 'Boot' })
        $shutdown = @($near | Where-Object { $_.Kind -eq 'Shutdown' })
        $facts = New-Object 'System.Collections.Generic.List[string]'
        $hypotheses = New-Object 'System.Collections.Generic.List[object]'
        $incidentGaps = New-Object 'System.Collections.Generic.List[string]'
        $status = 'Unresolved'
        if ($unexpected.Count) {
            $facts.Add('Windows recorded an unexpected shutdown indicator during recovery. Its timestamp is not necessarily the time power was lost.')
            $incidentGaps.Add('Exact failure time is unknown. Pre-recovery events may belong to normal operation or a later boot; EventLog 6008 embedded local time is not parsed.')
            $status = 'UnexpectedShutdownUnresolved'
        }
        if ($bug.Count -or $kpBug.Count) {
            $status = 'BugcheckRecorded'
            $facts.Add('Windows recorded bugcheck evidence. No dump contents, debugger output, symbols, or stack were analyzed.')
            $hypotheses.Add((New-Hypothesis 'RecordedMechanism' 'Bugcheck recorded; underlying cause unresolved' 'Direct Windows event evidence' @($bug + $kpBug) 'A bugcheck is a recorded failure mechanism, not a diagnosis of a specific driver or component.' 'Preserve the dump locally and arrange symbol-aware debugger analysis if a component-level diagnosis is needed.'))
        }
        if ($planned.Count) {
            $facts.Add('A process requested a planned shutdown or restart (USER32 1074); a request alone does not prove completion.')
            if ($unexpected.Count -or $bug.Count -or $kpBug.Count) {
                $facts.Add('Planned-request and unexpected-failure evidence coexist; the planned request does not explain away the failure.')
            } elseif ($boot.Count -and $shutdown.Count) {
                $ordered = $false
                foreach ($p in $planned) { foreach ($s in $shutdown) { foreach ($b in $boot) {
                    if ((ConvertTo-Instant $p.TimeCreated) -le (ConvertTo-Instant $s.TimeCreated) -and (ConvertTo-Instant $s.TimeCreated) -le (ConvertTo-Instant $b.TimeCreated) -and $p.RecordId -lt $s.RecordId -and $s.RecordId -lt $b.RecordId) { $ordered = $true }
                } } }
                if ($ordered) { $status = 'PlannedRebootObserved'; $facts.Add('Planned request, orderly shutdown, and subsequent boot occur in matching timestamp and System record order.') }
            } else { $status = 'PlannedRequestOnly' }
        }
        if ($boot.Count) { $facts.Add('Kernel-General 12 marks an OS start; EventLog 6005 alone only marks the event-log service starting.') }
        if (@($near | Where-Object { $_.Kind -in @('Sleep','Resume') }).Count) { $facts.Add('Sleep or resume activity is present and is not, on its own, evidence of a reboot.') }
        # Associate candidates only before the recovery boundary and after the previous
        # OS start. The failure itself can be earlier than this boundary.
        $boundaries = @($near | Where-Object { $_.Kind -in @('Boot','UnexpectedShutdown','Bugcheck') } | Sort-Object TimeUtc)
        $boundary = $at
        if ($boundaries.Count) { $boundary = ConvertTo-Instant $boundaries[0].TimeCreated }
        $previousBootLimit = $boundary.AddMinutes(-1).UtcDateTime.Ticks
        $lastBoot = @($bootIndex | Where-Object { $_.Ticks -lt $previousBootLimit } | Select-Object -Last 1 | ForEach-Object { $_.Event })
        foreach ($kind in @('Storage','Hardware','DriverService','Update')) {
            $allCandidates = @($near | Where-Object { $_.Kind -eq $kind })
            $candidates = @($allCandidates | Where-Object {
                $t = ConvertTo-Instant $_.TimeCreated
                $t -lt $boundary -and ($lastBoot.Count -eq 0 -or $t -ge (ConvertTo-Instant $lastBoot[0].TimeCreated))
            })
            if ($candidates.Count -and ($unexpected.Count -or $bug.Count -or $kpBug.Count)) {
                $title = @{Storage='Storage I/O errors near recovery';Hardware='Hardware error reports near recovery';DriverService='Driver or service failures near recovery';Update='Update activity near recovery'}[$kind]
                $explanation = 'Temporal association only. Events precede recovery, but may follow the actual failure; no causal link is established.'
                $next = @{Storage='Check backup health and review repeated controller/device errors with the storage vendor before any repair.';Hardware='Review recurring WHEA records and hardware diagnostics with the manufacturer; warnings alone do not identify a failed part.';DriverService='Compare recurrence and driver version history; use dump analysis before attributing the crash to a driver.';Update='Compare installation history and planned-restart requests; chronology alone cannot establish an update caused the failure.'}[$kind]
                $hypotheses.Add((New-Hypothesis 'PlausibleContributor' $title 'Limited temporal evidence' $candidates $explanation $next))
            }
            if ($allCandidates.Count -gt $candidates.Count) { $facts.Add($kind + ' events at or after the recovery boundary are coincident context; they are not ranked as preceding contributors.') }
        }
        if ($status -eq 'UnexpectedShutdownUnresolved') {
            $hypotheses.Insert(0,(New-Hypothesis 'Unresolved' 'Unexpected shutdown; cause unknown' 'Insufficient causal evidence' $unexpected 'Kernel-Power 41 and EventLog 6008 do not distinguish power loss, forced reset, hang, overheating, or hardware failure.' 'Record the observed failure time and symptoms, check external power connections safely, and compare repeated incidents.'))
        }
        if (-not $facts.Count) { $facts.Add('No mapped restart or crash evidence near the requested time.') }
        if (@($near | Where-Object { $_.Kind -eq 'DumpFailure' }).Count) { $incidentGaps.Add('Windows recorded dump initialization or creation failure; a missing dump is expected to remain inconclusive.') }
        $incidentGaps.Add('No component-level cause is confirmed. Nearby application failures, updates, and corrected WHEA warnings can be unrelated.')
        $incidents += [pscustomobject]@{
            Reference=('incident-{0:d3}' -f ($incidents.Count+1));AnchorTime=$at.ToString('o');Status=$status
            Facts=$facts.ToArray();RankedHypotheses=$hypotheses.ToArray();EvidenceGaps=$incidentGaps.ToArray();Timeline=@($near)
            RelatedDumps=@($safe.Dumps | Where-Object { [math]::Abs(((ConvertTo-Instant $_.LastWriteTime)-$at).TotalMinutes) -le 15 })
        }
    }
    if (-not $incidents.Count) { $gaps.Add('No mapped incident anchors in this bounded window. This does not establish that no crash occurred.') }
    [pscustomobject][ordered]@{
        SchemaVersion='1.0';DocumentType='Report';Privacy='SanitizedAllowlist';Window=$safe.Window;Context=$safe.Context
        Coverage=$safe.Coverage;InputNotes=$safe.InputNotes;DumpStatus=$safe.DumpStatus;Dumps=$safe.Dumps
        EvidenceGaps=$gaps.ToArray();Incidents=@($incidents);Timeline=@($events)
        Method='Ordinal ranking: recorded mechanism, unresolved mechanism, then storage, hardware, driver/service, and update temporal leads. Order is a review priority, never a probability. Recovery clusters use 10 minutes; context uses +/-15 minutes. Time changes weaken every proximity inference.'
    }
}

function ConvertTo-ReportText($Report) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Windows Crash Root Cause Analyzer - sanitized local report')
    $lines.Add('Window: ' + $Report.Window.Start + ' through ' + $Report.Window.End)
    $lines.Add('Windows version/build: ' + $Report.Context.WindowsVersion + '; architecture: ' + $Report.Context.Architecture)
    $lines.Add('Collection timezone: ' + $Report.Context.TimeZoneId + '. Each timestamp retains its observed offset; UTC is also shown.')
    $lines.Add($Report.Method)
    foreach ($gap in $Report.EvidenceGaps) { $lines.Add('Evidence gap: ' + $gap) }
    foreach ($coverage in $Report.Coverage) { $lines.Add(('Coverage: {0}: {1}; {2} mapped events; oldest available: {3}' -f $coverage.Channel,$coverage.Status,$coverage.Count,$coverage.OldestAvailable)) }
    $lines.Add('Duplicates removed: ' + $Report.InputNotes.Duplicates)
    foreach ($incident in $Report.Incidents) {
        $lines.Add(''); $lines.Add($incident.Reference + ' | ' + $incident.AnchorTime + ' | ' + $incident.Status)
        foreach ($fact in $incident.Facts) { $lines.Add('Observed fact: ' + $fact) }
        $rank = 0
        foreach ($hyp in $incident.RankedHypotheses) {
            $lines.Add(('Review rank {0}: [{1}] {2}; confidence: {3}' -f (++$rank),$hyp.Classification,$hyp.Title,$hyp.Confidence))
            $lines.Add('  ' + $hyp.Explanation); $lines.Add('  Evidence: ' + ($hyp.Evidence -join '; ')); $lines.Add('  Next test: ' + $hyp.NextTest)
        }
        foreach ($gap in $incident.EvidenceGaps) { $lines.Add('Evidence gap: ' + $gap) }
        foreach ($dump in $incident.RelatedDumps) { $lines.Add(('Nearby dump metadata: {0}; {1}; {2} bytes. Timestamp proximity is not identity.' -f $dump.Reference,$dump.LastWriteTime,$dump.SizeBytes)) }
    }
    $lines.Add(''); $lines.Add('Timeline (UTC order; preserve record IDs when clocks change):')
    foreach ($event in $Report.Timeline) {
        $lines.Add(('{0} | UTC {1} | {2} | {3} ID {4} v{5} record {6} | {7} | {8}' -f $event.TimeCreated,$event.TimeUtc,$event.Channel,$event.Provider,$event.Id,$event.Version,$event.RecordId,$event.Kind,($event.Data | ConvertTo-Json -Compress)))
    }
    $lines.Add('Privacy: free-form messages, identities, addresses, device identifiers, paths and dump names were omitted. Dump bytes were never read. Review before sharing; timestamps and configuration can still identify a system.')
    return $lines -join [Environment]::NewLine
}

function Write-JsonFile($Object, [string]$Path) {
    $json = $Object | ConvertTo-Json -Depth 30
    [IO.File]::WriteAllText($Path,$json,(New-Object Text.UTF8Encoding($false)))
}

function Write-IncidentReport($Report, [string]$OutputFolder, [string]$Format = 'Both') {
    $null = [IO.Directory]::CreateDirectory($OutputFolder)
    $jsonPath = Join-Path $OutputFolder 'report.json'
    if (Test-Path -LiteralPath $jsonPath) { throw 'Output already contains report.json; choose a new folder.' }
    $text = ConvertTo-ReportText $Report
    Write-JsonFile $Report $jsonPath
    if ($Format -in @('Text','Both')) { [IO.File]::WriteAllText((Join-Path $OutputFolder 'report.txt'),$text,(New-Object Text.UTF8Encoding($false))) }
    if ($Format -in @('Html','Both')) {
        $encoded = [Net.WebUtility]::HtmlEncode($text)
        $html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''"><title>Windows crash evidence</title><style>body{max-width:1100px;margin:2rem auto;padding:0 1rem;background:#101820;color:#e6edf3;font:15px/1.6 system-ui}pre{white-space:pre-wrap;overflow-wrap:anywhere}h1{color:#86d5cd}</style></head><body><h1>Windows crash evidence</h1><pre>' + $encoded + '</pre></body></html>'
        [IO.File]::WriteAllText((Join-Path $OutputFolder 'report.html'),$html,(New-Object Text.UTF8Encoding($false)))
    }
}



# Analyzer.Collect.psm1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Invoke-BoundedWorker {
    param([string]$Channel,[string]$Start,[string]$End,[int]$MaxEvents,[int]$TimeoutSeconds,[string]$ScratchFolder)
    $resultPath = Join-Path $ScratchFolder (([guid]::NewGuid().ToString('n')) + '.json')
    $workerPath = Join-Path $PSScriptRoot 'crash-analyzer.ps1'
    $hostPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $hostPath)) { $hostPath = Join-Path $PSHOME 'pwsh.exe' }
    $argsText = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $workerPath + '" -Worker -Channel "' + $Channel + '" -Start "' + $Start + '" -End "' + $End + '" -MaxEvents ' + $MaxEvents + ' -ResultPath "' + $resultPath + '"'
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$hostPath; $info.Arguments=$argsText; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $process = New-Object Diagnostics.Process
    $process.StartInfo=$info
    try {
        $null = $process.Start()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill(); $null = $process.WaitForExit(5000)
            return [pscustomobject]@{Channel=$Channel;Status='Timeout';OldestAvailable=$null;Events=@();Malformed=0;DumpStatus='Timeout';Dumps=@()}
        }
        if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $resultPath)) { throw 'Evidence collection could not finish. Try a shorter time window or check access to the event logs.' }
        if ((Get-Item -LiteralPath $resultPath).Length -gt 32MB) { throw 'Evidence collection exceeded its size limit. Try a shorter time window or fewer events.' }
        return ConvertFrom-JsonText ([IO.File]::ReadAllText($resultPath))
    } catch {
        return [pscustomobject]@{Channel=$Channel;Status='Error';OldestAvailable=$null;Events=@();Malformed=0;DumpStatus='Error';Dumps=@()}
    } finally {
        $process.Dispose()
        if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
    }
}

function Get-LocalEvidence {
    param([string]$Start,[string]$End,[int]$MaxEvents=2000,[int]$TimeoutSeconds=20,[string]$OutputFolder)
    $events = @(); $coverage = @(); $workerMalformed = 0
    foreach ($channel in @('System','Application','Microsoft-Windows-WindowsUpdateClient/Operational')) {
        Write-Host ('Reading event information: ' + $channel)
        $result = Invoke-BoundedWorker $channel $Start $End $MaxEvents $TimeoutSeconds $OutputFolder
        $events += @(Get-Value $result 'Events' @())
        $workerMalformed += [int](Get-Value $result 'Malformed' 0)
        $coverage += [pscustomobject]@{Channel=$channel;Status=$result.Status;OldestAvailable=$result.OldestAvailable}
    }
    $context = Invoke-BoundedWorker 'Context' $Start $End $MaxEvents $TimeoutSeconds $OutputFolder
    $evidence = Get-SafeEvidence ([pscustomobject]@{
        SchemaVersion='1.0';DocumentType='Evidence';CollectedAt=[DateTimeOffset]::UtcNow.ToString('o');Window=[pscustomobject]@{Start=$Start;End=$End}
        Context=(Get-Value $context 'Context');Coverage=@($coverage);Events=@($events)
        DumpStatus=(Get-Value $context 'DumpStatus' 'Error');Dumps=@(Get-Value $context 'Dumps' @())
    })
    # Count malformed XML without retaining unsafe record contents.
    $evidence.InputNotes.Malformed += $workerMalformed
    return $evidence
}



# Internal read-only function loading for worker/tests.
function Invoke-CollectionWorker {
    [CmdletBinding()]
    param(
        [ValidateSet('System','Application','Microsoft-Windows-WindowsUpdateClient/Operational','Context')][string]$Channel,
        [string]$Start,[string]$End,
        [ValidateRange(1,10000)][int]$MaxEvents=2000,
        [Parameter(Mandatory=$true)][string]$ResultPath
    )
$result = $null
try {
    if ($Channel -eq 'Context') {
        $version = 'Unknown'
        try {
            $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $version = '10.0.' + $os.CurrentBuildNumber + '.' + $os.UBR
        } catch {}
        $context = [pscustomobject]@{WindowsVersion=$version;Architecture=$env:PROCESSOR_ARCHITECTURE;TimeZoneId=[TimeZoneInfo]::Local.Id}
        $dumps = New-Object 'System.Collections.Generic.List[object]'
        $dumpStatus = 'NoneFound'
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $minidump = Join-Path $windows 'Minidump'
        # Enumerate metadata only, never open a dump stream or recurse.
        try {
            if ([IO.Directory]::Exists($minidump)) {
                foreach ($path in [IO.Directory]::EnumerateFiles($minidump,'*.dmp',[IO.SearchOption]::TopDirectoryOnly)) {
                    if ($dumps.Count -ge 256) { $dumpStatus = 'Truncated'; break }
                    $file = New-Object IO.FileInfo($path)
                    $dumps.Add([pscustomobject]@{SizeBytes=$file.Length;LastWriteTime=$file.LastWriteTimeUtc.ToString('o')})
                }
            } else {
                # Directory.Exists alone hides access-denied errors; distinguish them.
                $null = Get-Item -LiteralPath $minidump -ErrorAction Stop
            }
        } catch [UnauthorizedAccessException] { $dumpStatus = 'AccessDenied' }
          catch [System.Management.Automation.ItemNotFoundException] { $dumpStatus = 'NoneFound' }
          catch { $dumpStatus = 'Error' }
        try {
            $fullDump = Join-Path $windows 'MEMORY.DMP'
            $file = Get-Item -LiteralPath $fullDump -ErrorAction Stop
            if ($dumps.Count -lt 256) { $dumps.Add([pscustomobject]@{SizeBytes=$file.Length;LastWriteTime=$file.LastWriteTimeUtc.ToString('o')}) } else { $dumpStatus = 'Truncated' }
        } catch [UnauthorizedAccessException] { $dumpStatus = 'AccessDenied' }
          catch [System.Management.Automation.ItemNotFoundException] {}
          catch { $dumpStatus = 'Error' }
        if ($dumps.Count -and $dumpStatus -eq 'NoneFound') { $dumpStatus = 'Found' }
        $result = [pscustomobject]@{Context=$context;Dumps=$dumps.ToArray();DumpStatus=$dumpStatus}
    } else {
        $startTime = (ConvertTo-Instant $Start).UtcDateTime.ToString('o')
        $endTime = (ConvertTo-Instant $End).UtcDateTime.ToString('o')
        $events = New-Object 'System.Collections.Generic.List[object]'
        $status = 'Complete'; $oldest = $null; $malformed = 0
        # Discovery doesn't enable a disabled/missing channel.
        $log = Get-WinEvent -ListLog $Channel -ErrorAction Stop
        if (-not $log.IsEnabled) {
            $status = 'Unavailable'
        } else {
            try {
                $first = Get-WinEvent -LogName $Channel -Oldest -MaxEvents 1 -ErrorAction Stop
                $oldest = $first.TimeCreated.ToUniversalTime().ToString('o')
                $first.Dispose()
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            }
            $query = Get-EventQueryXml $Channel $startTime $endTime
            $readCount = 0
            try {
                Get-WinEvent -FilterXml $query -MaxEvents ($MaxEvents+1) -ErrorAction Stop | ForEach-Object {
                    $nativeEvent = $_
                    try {
                        $readCount++
                        if ($readCount -gt $MaxEvents) { $status = 'Truncated' }
                        else { try { $event = ConvertFrom-EventXml $nativeEvent.ToXml(); if ($event) { $events.Add($event) } } catch { $malformed++ } }
                    } finally { $nativeEvent.Dispose() }
                }
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            }
        }
        $result = [pscustomobject]@{Channel=$Channel;Status=$status;OldestAvailable=$oldest;Events=$events.ToArray();Malformed=$malformed}
    }
} catch {
    $status = 'Error'
    if ($_.Exception -is [UnauthorizedAccessException] -or $_.FullyQualifiedErrorId -like '*Unauthorized*') { $status = 'AccessDenied' }
    elseif ($_.FullyQualifiedErrorId -like '*NoMatchingLogsFound*') { $status = 'Unavailable' }
    # Exception messages can contain identities or paths; emit only fixed codes.
    $result = [pscustomobject]@{Channel=$Channel;Status=$status;OldestAvailable=$null;Events=@();Malformed=0;DumpStatus=$status;Dumps=@()}
}
Write-JsonFile $result $ResultPath

}

try {
    if ($Command -notin @('analyze','collect','report','help')) { throw 'Choose analyze, collect, report or help as the command.' }
    if ($Format -notin @('Html','Text','Both')) { throw '-Format must be Html, Text or Both.' }
    try { [int]$Days = $Days; [int]$MaxEventsPerChannel = $MaxEventsPerChannel; [int]$QueryTimeoutSeconds = $QueryTimeoutSeconds }
    catch { throw 'Use whole numbers for -Days, -MaxEventsPerChannel and -QueryTimeoutSeconds.' }
    if ($Days -lt 1 -or $Days -gt 366) { throw '-Days must be from 1 to 366.' }
    if ($MaxEventsPerChannel -lt 1 -or $MaxEventsPerChannel -gt 10000) { throw '-MaxEventsPerChannel must be from 1 to 10000.' }
    if ($QueryTimeoutSeconds -lt 1 -or $QueryTimeoutSeconds -gt 60) { throw '-QueryTimeoutSeconds must be from 1 to 60.' }
} catch {
    [Console]::Error.WriteLine('ERROR: ' + $_.Exception.Message + ' Run crash-analyzer.bat help for usage.')
    exit 1
}

if ($Worker) {
    Invoke-CollectionWorker -Channel $Channel -Start $Start -End $End -MaxEvents $MaxEvents -ResultPath $ResultPath
    exit 0
}

if ($Library) { return }

try {
    if ($Command -eq 'help') {
        Write-Output @'
Windows Crash Root Cause Analyzer - read-only Windows crash reports

Usage:
  crash-analyzer.bat analyze
  crash-analyzer.bat analyze -Days 3 -IncidentTime "2026-10-21T18:00:00-07:00"
  crash-analyzer.bat collect -Days 1 -OutputFolder "C:\Captures\new evidence"
  crash-analyzer.bat report -InputFile "C:\Captures\new evidence\evidence.json"
  crash-analyzer.bat help

Commands:
  analyze  Collect evidence and create HTML, text and JSON reports.
  collect  Save evidence.json for later reporting.
  report   Read this tool's evidence JSON (version 1.0), without collecting events.
           Raw EVTX and crash-dump files are not report inputs.

Options:
  -Days                 Days to examine (default 7; range 1-366).
  -StartTime, -EndTime   Optional start/end times instead of the default window.
  -IncidentTime         Focus on one time and its 15-minute surroundings.
  -MaxEventsPerChannel  Event limit per log (default 2000; range 1-10000).
  -QueryTimeoutSeconds  Time limit per collection step (default 20; range 1-60).
  -InputFile            Existing evidence JSON; required by report.
  -Format               Html, Text or Both (default Both).
  -OutputFolder         New or empty local folder. Default: a new output/ subfolder
                        beside the script. Existing reports are never overwritten.

Times need an offset or Z, for example 2026-10-21T18:00:00-07:00.
The window ends now unless -EndTime is supplied; its maximum span is 366 days.
Quote paths containing spaces. In PowerShell, prefix BAT commands with .\.

No repairs, settings changes, reboots, dump-content reads, telemetry or uploads.
Start without administrator rights; inaccessible logs are reported as missing evidence.
Kernel-Power 41 alone cannot identify a failed component. Recovery times may differ
from crash times. Review Coverage and EvidenceGaps before drawing conclusions.
Reports omit names, private paths and event-message text; times/build details may
still identify your machine. Review reports before sharing.
Exit codes: 0 completed, including partial evidence; 1 invalid input/failure.
'@
        exit 0
    }
    if ($InputFile -and $Command -ne 'report') { throw 'InputFile is supported only by report.' }
    if ($Command -eq 'report' -and -not $InputFile) { throw 'report requires InputFile.' }
    if ($Command -eq 'report' -and ($StartTime -or $EndTime -or $PSBoundParameters.ContainsKey('Days'))) { throw 'report uses the window stored in its input file.' }
    # Worker parameters Start/End are strings; keep the main window strongly typed.
    $windowStart = $null; $windowEnd = $null
    if ($Command -ne 'report') {
        $windowEnd = [DateTimeOffset]::Now
        if ($EndTime) { $windowEnd = ConvertTo-Instant $EndTime }
        $windowStart = $windowEnd.AddDays(-$Days)
        if ($StartTime) { $windowStart = ConvertTo-Instant $StartTime }
        if ($windowStart -gt $windowEnd -or ($windowEnd - $windowStart).TotalDays -gt 366) { throw 'Time window must span 0 to 366 days.' }
    }
    if ($IncidentTime) {
        $incident = ConvertTo-Instant $IncidentTime
        if ($Command -eq 'collect') { throw 'IncidentTime is used by analyze or report, not collect.' }
        if ($windowStart -and ($incident -lt $windowStart -or $incident -gt $windowEnd)) { throw 'Incident time is outside the collection window; specify StartTime/EndTime or Days.' }
    }
    $evidence = $null
    if ($Command -eq 'report') {
        if ($InputFile.StartsWith('\\') -or $InputFile -match '^[a-zA-Z]+://') { throw 'InputFile must be a local file.' }
        $inputPath = [IO.Path]::GetFullPath($InputFile)
        $inputDrive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($inputPath))
        if ($inputDrive.DriveType -eq [IO.DriveType]::Network) { throw 'InputFile must be on a local drive.' }
        $inputCursor = $inputPath
        while ($inputCursor) {
            if (Test-Path -LiteralPath $inputCursor) {
                $inputNode = Get-Item -LiteralPath $inputCursor -Force
                if ($inputNode.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'InputFile must be reached without symbolic links or folder junctions.' }
            }
            $inputCursor = [IO.Path]::GetDirectoryName($inputCursor)
        }
        $item = Get-Item -LiteralPath $inputPath
        if ($item.Length -gt 32MB -or $item.PSIsContainer) { throw 'Input must be an evidence JSON file no larger than 32 MiB.' }
        $evidence = ConvertFrom-JsonText ([IO.File]::ReadAllText($inputPath))
        # Validate and construct the report before creating output directories.
        $report = Get-IncidentReport $evidence $IncidentTime
    }
    if (-not $OutputFolder) { $OutputFolder = Join-Path $PSScriptRoot ('output\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('n').Substring(0,8)) }
    if ($OutputFolder.StartsWith('\\') -or $OutputFolder -match '^[a-zA-Z]+://') { throw 'OutputFolder must be local.' }
    $outputPath = [IO.Path]::GetFullPath($OutputFolder)
    $driveRoot = [IO.Path]::GetPathRoot($outputPath)
    $drive = New-Object IO.DriveInfo($driveRoot)
    if ($drive.DriveType -eq [IO.DriveType]::Network) { throw 'Mapped network drives are not supported.' }
    # Reject junctions/symlinks to avoid silently writing across an output boundary.
    $cursor = $outputPath
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $node = Get-Item -LiteralPath $cursor -Force
            if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Output paths must be reached without symbolic links or folder junctions.' }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    if (Test-Path -LiteralPath $outputPath) {
        if (-not (Test-Path -LiteralPath $outputPath -PathType Container) -or @(Get-ChildItem -LiteralPath $outputPath -Force).Count) { throw 'Choose a new or empty output folder.' }
    }
    $null = [IO.Directory]::CreateDirectory($outputPath)
    if ($Command -ne 'report') {
        $evidence = Get-LocalEvidence -Start $windowStart.ToString('o') -End $windowEnd.ToString('o') -MaxEvents $MaxEventsPerChannel -TimeoutSeconds $QueryTimeoutSeconds -OutputFolder $outputPath
        Write-JsonFile $evidence (Join-Path $outputPath 'evidence.json')
        if ($Command -eq 'analyze') { $report = Get-IncidentReport $evidence $IncidentTime }
    }
    if ($Command -ne 'collect') { Write-IncidentReport $report $outputPath $Format }
    $coverage = $(if ($Command -eq 'report') { $report.Coverage } else { $evidence.Coverage })
    $incompleteSources = @($coverage | Where-Object { $_.Status -ne 'Complete' }).Count
    Write-Host ('Event channels: {0} complete; {1} partial/unavailable. Review Coverage before drawing conclusions.' -f (@($coverage).Count - $incompleteSources), $incompleteSources)
    if ($Command -ne 'collect') {
        $gapCount = @($report.EvidenceGaps).Count
        foreach ($item in @($report.Incidents)) { $gapCount += @($item.EvidenceGaps).Count }
        Write-Host ('Report: {0} incident(s); {1} evidence gap(s). These findings do not confirm which component caused the crash.' -f @($report.Incidents).Count, $gapCount)
    }
    Write-Host ('Local output: ' + $outputPath)
    exit 0
} catch {
    # Parameter errors from the binder can include supplied values; runtime errors
    # use only our fixed messages or exception types, never event payloads.
    if ($_.Exception -is [System.Management.Automation.RuntimeException] -and $_.Exception.Message -match '^(Timestamp|Time window|Incident|InputFile|report |Output|Mapped|Choose|Unsupported|Evidence |Input must|Worker)') {
        [Console]::Error.WriteLine('ERROR: ' + $_.Exception.Message)
    } else { [Console]::Error.WriteLine('ERROR: Could not finish. Check the input evidence file, local folders and access permissions. Run crash-analyzer.bat help for usage.') }
    exit 1
}

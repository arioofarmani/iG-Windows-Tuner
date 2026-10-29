# ForensicPage.ps1
# Security > Firewall > Forensic logging (3.5): the three sources with their state and who manages
# them, a profile (Basic, Full, Custom), a preview of every change, a time-boxed session that is
# restored automatically while the app is open, and a window banner while a session runs or when one
# expired while the app was closed. Changes go through Start-/Stop-IgwtForensicLoggingSession only
# (snapshot first); they are off in read-only mode.

function Initialize-IgwtGuiForensicPage {
    <# .SYNOPSIS Wires the Forensic logging tab and the banner, and checks for a session (called once by the Firewall page). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Wires window objects only.')]
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $script:Gui.Forensic = @{ State = $null; Stopping = $false; Timer = $null }
    Register-IgwtGuiHandler -Control $c.FwForRefreshButton -Event 'Click' -Handler { Start-IgwtGuiForensicRefresh }
    Register-IgwtGuiHandler -Control $c.FwForPreviewButton -Event 'Click' -Handler { Invoke-IgwtGuiForensicPreview }
    Register-IgwtGuiHandler -Control $c.FwForStartButton -Event 'Click' -Handler { Invoke-IgwtGuiForensicPreview -Start }
    Register-IgwtGuiHandler -Control $c.FwForStopButton -Event 'Click' -Handler { Invoke-IgwtGuiForensicStop }
    Register-IgwtGuiHandler -Control $c.ForensicBannerStopButton -Event 'Click' -Handler { Invoke-IgwtGuiForensicStop }
    Register-IgwtGuiHandler -Control $c.ForensicBannerOpenButton -Event 'Click' -Handler { Select-IgwtGuiNavPage -Tag 'Firewall'; $script:Gui.C.FwTabs.SelectedItem = $script:Gui.C.FwForensicTab }
    Register-IgwtGuiHandler -Control $c.FwForEstimateButton -Event 'Click' -Handler { Invoke-IgwtGuiForensicEstimate }
    foreach ($n in 'FwForBasic', 'FwForFull', 'FwForCustom') { Register-IgwtGuiHandler -Control $c[$n] -Event 'Checked' -Handler { Update-IgwtGuiForensicChoice } }
    Update-IgwtGuiForensicChoice
    $writable = -not (Test-IgwtReadOnly)
    $c.FwForStartButton.IsEnabled = $writable; $c.FwForStopButton.IsEnabled = $writable; $c.ForensicBannerStopButton.IsEnabled = $writable
    if (-not $writable) { $c.FwForStartButton.ToolTip = 'Off in read-only mode.'; $c.FwForStopButton.ToolTip = 'Off in read-only mode.'; $c.ForensicBannerStopButton.ToolTip = 'Off in read-only mode: restart iG Windows Tuner without -ReadOnly, as administrator, to restore.' }
    # The session clock: no scheduled task (no-persistence rule), so the window checks every 30 seconds.
    $t = New-Object System.Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromSeconds(30)
    Register-IgwtGuiHandler -Control $t -Event 'Tick' -Handler { Update-IgwtGuiForensicSession }
    $script:Gui.Forensic.Timer = $t
    Update-IgwtGuiForensicSession
    $t.Start()
}

function Update-IgwtGuiForensicChoice {
    <# .SYNOPSIS Custom source boxes are only active for the Custom profile. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param()
    $script:Gui.C.FwForCustomPanel.IsEnabled = [bool]$script:Gui.C.FwForCustom.IsChecked
}

function Get-IgwtGuiForensicChoice {
    <# .SYNOPSIS The profile, sources, Security log size and duration chosen on the tab. #>
    [CmdletBinding()]
    param()
    $c = $script:Gui.C
    $mode = $(if ($c.FwForFull.IsChecked) { 'Full' } elseif ($c.FwForCustom.IsChecked) { 'Custom' } else { 'Basic' })
    @{
        Profile = $mode
        Options = @{ FirewallBlocked = [bool]$c.FwForFwBlocked.IsChecked; FirewallAllowed = [bool]$c.FwForFwAllowed.IsChecked; WfpConnection = [bool]$c.FwForWfpConn.IsChecked; WfpPacketDrop = [bool]$c.FwForWfpDrop.IsChecked; DnsClient = [bool]$c.FwForDns.IsChecked }
        SecurityLogMB = @(256, 512, 1024)[[Math]::Max(0, $c.FwForSizeBox.SelectedIndex)]
        Minutes = @(30, 120, 480, 0)[[Math]::Max(0, $c.FwForDurationBox.SelectedIndex)]
    }
}

function Start-IgwtGuiForensicRefresh {
    <# .SYNOPSIS Reads the state of the sources in the background (read-only). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only query.')]
    [CmdletBinding()]
    param()
    $script:Gui.C.FwForStatusText.Text = 'Reading the logging settings...'
    $null = Start-IgwtGuiJob -Command 'Get-IgwtForensicLoggingState' -Channel 'forensic' -BusyText 'Reading the forensic logging settings (read-only)...' -OnComplete {
        param($out, $errs)
        $s = @($out) | Select-Object -Last 1
        if (-not $s) { $script:Gui.C.FwForStatusText.Text = "The logging settings could not be read: $(@($errs)[0])"; return }
        Set-IgwtGuiForensicState -State $s
    }
}

function Set-IgwtGuiForensicState {
    <# .SYNOPSIS Shows the three source cards (what each records, volume, state, who manages it). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State)
    $c = $script:Gui.C
    $script:Gui.Forensic.State = $State
    $fw = @($State.Firewall)
    $fwState = (@($fw | ForEach-Object { "$($_.Profile): $(if ($_.LogBlocked) { 'blocked' } else { 'no blocked' })$(if ($_.LogAllowed) { ' + allowed' })" }) -join '; ')
    $fwManaged = @($fw | Where-Object { $_.ManagedBy -eq 'Policy' } | ForEach-Object { $_.Profile })
    $wfp = $State.Wfp
    $sec = $State.SecurityLog
    $dns = $State.Dns
    $c.FwForSources.ItemsSource = @(
        [pscustomobject]@{ Title = 'Firewall packet log'; State = $fwState
            Records = 'Allowed and dropped packets per profile: time, addresses, ports, protocol, direction. No program names (newer Windows adds a process id).'
            Volume = 'Volume: low for blocked packets, high with allowed ones. Size up to 32 MB per file (Windows limit).'
            Managed = $(if ($fwManaged.Count) { "Set by a policy for: $($fwManaged -join ', ') (read-only here)." } else { 'Managed locally.' })
            Tip = 'Uses the default path %windir%\system32\LogFiles\Firewall\pfirewall.log; a custom folder needs write access for the Windows Defender Firewall service.' }
        [pscustomobject]@{ Title = 'WFP connection auditing'; State = $(if ($wfp.Readable) { "Connections: $($wfp.Connection); packet drops: $($wfp.PacketDrop)" } else { 'Unknown: reading the audit policy needs administrator rights.' })
            Records = 'Every permitted and blocked connection with the program path and process id (Security events 5156 and 5157; 5152 for dropped packets).'
            Volume = 'Volume: very high (one event per connection). The Security log is enlarged first.'
            Managed = $(if ($wfp.ManagedBy -eq 'Policy') { "This PC is managed ($(@($wfp.Authorities) -join ', ')): the audit policy comes from there (read-only here)." } else { 'Managed locally.' })
            Tip = 'Audit subcategories Filtering Platform Connection {0CCE9226-69AE-11D9-BED3-505054503030} and Packet Drop {0CCE9225-69AE-11D9-BED3-505054503030}, set by GUID.' }
        [pscustomobject]@{ Title = 'DNS client log'; State = $(if ($dns) { if ($dns.Enabled) { 'On' } else { 'Off (Windows default)' } } else { 'Unknown' })
            Records = 'The names programs look up, with the process id: puts names behind the addresses in the other logs.'
            Volume = 'Volume: moderate.'
            Managed = 'Managed locally.'
            Tip = 'Event log Microsoft-Windows-DNS-Client/Operational.' }
    )
    $secText = $(if ($sec) { 'Security log: {0:N0} MB{1}.' -f ($sec.MaxSizeBytes / 1MB), $(if ($sec.ManagedBy -eq 'Policy') { ', size set by a policy' } else { '' }) } else { '' })
    $c.FwForStatusText.Text = (@($secText) + @($State.Notes) | Where-Object { $_ }) -join ' '
    Update-IgwtGuiForensicBanner -Session $State.Session
}

function Format-IgwtGuiForensicPlan {
    <# .SYNOPSIS A plan as plain text for the preview dialog. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Plan, [int]$Minutes)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Forensic logging, profile $($Plan.Profile), $(if ($Minutes) { "for $(if ($Minutes -ge 60) { "$($Minutes / 60) hour(s)" } else { "$Minutes minutes" })" } else { 'until you stop it' }).")
    $lines.Add('')
    foreach ($op in @($Plan.Ops)) {
        $state = $(if ($op.Refused) { "not changed: $($op.Refused)" } elseif ($op.Changes) { "$($op.Current) -> $($op.New)" } else { "already $($op.New)" })
        $lines.Add(("  {0,-12} {1,-32} {2,-13} {3}" -f $op.Source, $op.Target, $op.Setting, $state))
    }
    $lines.Add('')
    $lines.Add("$($Plan.Changes) change(s). Every setting is saved first and restored exactly when the session ends. Event logs are never cleared.")
    foreach ($n in @($Plan.Notes)) { $lines.Add($n) }
    return ($lines -join [Environment]::NewLine)
}

function Invoke-IgwtGuiForensicPreview {
    <# .SYNOPSIS Shows what the chosen profile changes; with -Start, starts the session after the user accepts. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Shows a preview; the change runs through Start-IgwtForensicLoggingSession after confirmation.')]
    [CmdletBinding()]
    param([switch]$Start)
    if ($Start -and ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin)) { Set-IgwtGuiStatus 'Forensic logging needs administrator rights and is off in read-only mode.'; return }
    $choice = Get-IgwtGuiForensicChoice
    $null = Start-IgwtGuiJob -Command 'Get-IgwtForensicLoggingPlan' -Parameters @{ LoggingProfile = $choice.Profile; Options = $choice.Options; SecurityLogMB = $choice.SecurityLogMB } -Channel 'forensic-plan' -BusyText 'Preparing the forensic logging preview (read-only)...' -Context @{ Choice = $choice; Start = [bool]$Start } -OnComplete {
        param($out, $errs, $ctx)
        $plan = @($out) | Select-Object -Last 1
        if (-not $plan) { Show-IgwtGuiError -Message "The preview could not be made: $(@($errs)[0])" -Context 'Forensic logging'; return }
        $text = Format-IgwtGuiForensicPlan -Plan $plan -Minutes $ctx.Choice.Minutes
        if (-not $ctx.Start -or -not $plan.Changes) { $null = Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - forensic logging preview' -Text $text; return }
        if (-not (Show-IgwtGuiTextDialog -Title 'iG Windows Tuner - start forensic logging' -Text $text -AcceptText 'Start forensic logging' -CancelText 'Cancel')) { return }
        $null = Start-IgwtGuiJob -Command 'Start-IgwtForensicLoggingSession' -Parameters @{ Plan = $plan; Minutes = $ctx.Choice.Minutes; Confirm = $false } -Blocking -BusyText 'Saving the settings and starting forensic logging...' -OnComplete {
            param($o2, $e2)
            $s = @($o2) | Select-Object -Last 1
            if (-not $s) { Show-IgwtGuiError -Message "Forensic logging was not started (the settings were restored): $(@($e2)[0])" -Context 'Forensic logging' }
            else { Show-IgwtGuiToast -Text 'Forensic logging started. The previous settings come back when the session ends.' -Tone Success }
            Start-IgwtGuiForensicRefresh
        }
    }
}

function Invoke-IgwtGuiForensicStop {
    <# .SYNOPSIS Ends the session and restores every setting (after confirmation). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Asks first; the change runs through Stop-IgwtForensicLoggingSession.')]
    [CmdletBinding()]
    param([switch]$Automatic)
    if ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) { Set-IgwtGuiStatus 'Restoring the logging settings needs administrator rights and is off in read-only mode.'; return }
    if (-not (Get-IgwtForensicSession)) { Set-IgwtGuiStatus 'No forensic logging session is running.'; return }
    if (-not $Automatic -and (Show-IgwtGuiMessage -Text "Stop forensic logging and restore every setting it changed?`n`nCollected logs and events stay." -Title 'iG Windows Tuner - forensic logging' -Buttons 'YesNo' -Icon 'Question') -ne 'Yes') { return }
    if ($script:Gui.Forensic.Stopping) { return }
    $script:Gui.Forensic.Stopping = $true
    $null = Start-IgwtGuiJob -Command 'Stop-IgwtForensicLoggingSession' -Parameters @{ Confirm = $false } -Blocking -BusyText 'Restoring the logging settings...' -OnComplete {
        param($out, $errs)
        $script:Gui.Forensic.Stopping = $false
        $r = @($out) | Select-Object -Last 1
        if (-not $r -or -not $r.Stopped) { Show-IgwtGuiError -Message $(if ($r) { $r.Message } else { "Forensic logging could not be stopped: $(@($errs)[0])" }) -Context 'Forensic logging' }
        else { Show-IgwtGuiToast -Text $r.Message -Tone Success }
        Update-IgwtGuiForensicSession
        Start-IgwtGuiForensicRefresh
    }
}

function Update-IgwtGuiForensicSession {
    <# .SYNOPSIS The session clock: updates the banner and restores the settings when the session has ended. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window; a restore runs through Stop-IgwtForensicLoggingSession.')]
    [CmdletBinding()]
    param()
    $s = $null
    try { $s = Get-IgwtForensicSession } catch { Write-Verbose "Session not read: $($_.Exception.Message)" }
    Update-IgwtGuiForensicBanner -Session $s
    # Ended while the app is open: restore automatically (needs a writable, elevated window).
    if ($s -and -not $s.Corrupt -and $s.Expired -and $script:Gui.Forensic.Running -and -not (Test-IgwtReadOnly) -and $script:Gui.IsAdmin) { Invoke-IgwtGuiForensicStop -Automatic }
    $script:Gui.Forensic.Running = [bool]($s -and -not $s.Expired)
}

function Update-IgwtGuiForensicBanner {
    <# .SYNOPSIS The window banner: an active session (since, until), or one that ended while the app was closed. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes the window only.')]
    [CmdletBinding()]
    param($Session)
    $c = $script:Gui.C
    if (-not $Session) { $c.ForensicBanner.Visibility = 'Collapsed'; return }
    $c.ForensicBanner.Visibility = 'Visible'
    if ($Session.Corrupt) { $c.ForensicBannerText.Text = "$($Session.Message) The snapshot folders are in %ProgramData%\iGWindowsTuner\Backups (forensic-*)."; return }
    $since = '{0:HH:mm}' -f $Session.Started
    if ($Session.Expired -and -not $script:Gui.Forensic.Running) {
        $c.ForensicBannerText.Text = "A forensic logging session ended at $('{0:yyyy-MM-dd HH:mm}' -f $Session.Until) while iG Windows Tuner was closed; its settings are still on. Stop and restore them now$(if ((Test-IgwtReadOnly) -or -not $script:Gui.IsAdmin) { ' (needs administrator rights, not in read-only mode)' })."
    } else {
        $c.ForensicBannerText.Text = "Forensic logging active since $since ($($Session.Profile))$(if ($Session.Until) { "; restored automatically at $('{0:HH:mm}' -f $Session.Until) while iG Windows Tuner is open" } else { '; until you stop it' })."
    }
}

function Invoke-IgwtGuiForensicEstimate {
    <# .SYNOPSIS Samples new connections for 10 seconds (read-only) and shows events per hour and retention per log size. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Starts a read-only measurement.')]
    [CmdletBinding()]
    param()
    $script:Gui.C.FwForEstimateText.Text = 'Watching new connections for 10 seconds...'
    $null = Start-IgwtGuiJob -Command 'Measure-IgwtConnectionRate' -Parameters @{ Seconds = 10 } -Channel 'forensic-estimate' -BusyText 'Sampling the connection table for 10 seconds (read-only)...' -OnComplete {
        param($out, $errs)
        $m = @($out) | Select-Object -Last 1
        if (-not $m) { $script:Gui.C.FwForEstimateText.Text = "The estimate failed: $(@($errs)[0])"; return }
        $e = Get-IgwtForensicVolumeEstimate -ConnectionsPerHour $m.PerHour
        $ret = (@($e.Retention | ForEach-Object { '{0} MB about {1} h' -f $_.SizeMB, $_.Hours }) -join ', ')
        $script:Gui.C.FwForEstimateText.Text = ('{0} new connections in {1} s: about {2:N0} WFP events per hour. Security log retention: {3}. {4} Use the PC as you normally would while measuring.' -f $m.New, $m.Seconds, $e.EventsPerHour, $ret, $e.Assumption)
    }
}

# Parser-based inventory of state-changing calls in src (DECISIONS T12), shared by
# tests\OneEngine.Tests.ps1. Returns one row per call: File, Function, Line, Command.
# Read-only: it parses the files and runs nothing.

$script:IgwtStateCmdlets = @(
    'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Rename-ItemProperty', 'Clear-ItemProperty',
    'Set-Service', 'Stop-Service', 'Start-Service', 'Restart-Service',
    'Set-NetFirewallProfile', 'New-NetFirewallRule', 'Set-NetFirewallRule', 'Remove-NetFirewallRule', 'Enable-NetFirewallRule', 'Disable-NetFirewallRule',
    'Set-NetConnectionProfile', 'Set-NetTCPSetting', 'Set-NetAdapterAdvancedProperty', 'Reset-NetAdapterAdvancedProperty', 'Set-NetAdapterPowerManagement',
    'Set-NetAdapterBinding', 'Enable-NetAdapterBinding', 'Disable-NetAdapterBinding', 'Set-NetAdapterRss', 'Set-NetAdapterLso', 'Set-NetAdapter', 'Enable-NetAdapter', 'Disable-NetAdapter', 'Restart-NetAdapter',
    'New-NetQosPolicy', 'Set-NetQosPolicy', 'Remove-NetQosPolicy', 'Set-DnsClientServerAddress', 'Set-DnsClient', 'Set-DnsClientDohServerAddress', 'Add-DnsClientDohServerAddress', 'Remove-DnsClientDohServerAddress', 'Set-DnsClientGlobalSetting',
    'Set-MpPreference', 'Add-MpPreference', 'Remove-MpPreference', 'Start-MpScan', 'Remove-MpThreat',
    'Register-ScheduledTask', 'Set-ScheduledTask', 'Unregister-ScheduledTask', 'Enable-ScheduledTask', 'Disable-ScheduledTask',
    'Set-ProcessMitigation', 'Enable-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature', 'Add-WindowsCapability', 'Remove-WindowsCapability',
    'Add-AppxPackage', 'Remove-AppxPackage', 'Remove-AppxProvisionedPackage', 'Enable-PnpDevice', 'Disable-PnpDevice', 'Checkpoint-Computer', 'Enable-ComputerRestore'
)
# Native tools: name -> regex on the joined arguments that marks a write ('' = every call writes).
$script:IgwtStateTools = [ordered]@{
    'sc'       = '^(config|failure|start|stop|delete|create|sdset)\b'
    'reg'      = '^(add|delete|import|restore|load|unload|copy)\b'
    'powercfg' = '(?i)(^|\s)[/-](s|setactive|change|x|setacvalueindex|setdcvalueindex|attributes|h|hibernate|duplicatescheme|d|delete|import|restoredefaultschemes|changename|setsecuritydescriptor)\b'
    'auditpol' = '(?i)(^|\s)/(set|restore|clear|remove)\b'
    'wevtutil' = '(?i)^(sl|set-log|cl|clear-log|im|install-manifest|um)\b'
    'schtasks' = '(?i)(^|\s)/(create|change|delete|run|end)\b'
    'bcdedit'  = ''
    'secedit'  = '(?i)(^|\s)/configure\b'
    'gpupdate' = ''
    'winget'   = '(?i)^(install|uninstall|upgrade|update|remove|import|configure|repair)\b'
    'netsh'    = '(?i)\b(set|add|delete|reset)\b'
}
# The tool's own runners for native tools (src calls the tools only through them): name -> regex
# on the call's text that marks a write ('' = every call writes).
$script:IgwtStateWrappers = [ordered]@{
    'Invoke-IgwtPowerCfg'    = '(?i)[''"][/-](s|setactive|change|x|setacvalueindex|setdcvalueindex|attributes|h|hibernate|duplicatescheme|d|delete|import|restoredefaultschemes|changename)[''"]'
    'Invoke-IgwtAuditpol'    = '(?i)[''"]/(set|restore|clear|remove)\b'
    'Invoke-IgwtWevtutil'    = '(?i)[''"](sl|set-log|cl|clear-log)[''"]|\$a\b'
    'Invoke-IgwtSecedit'     = '(?i)/configure'
    'Invoke-IgwtGpUpdate'    = ''
    'Invoke-IgwtWinget'      = '(?i)[''"](install|uninstall|upgrade|remove|import)[''"]'
    'Write-IgwtRegistryPol'  = ''
}
# .NET registry writes.
$script:IgwtStateMembers = @('SetValue', 'DeleteValue', 'CreateSubKey', 'DeleteSubKey', 'DeleteSubKeyTree')

function Get-IgwtStateChangingCall {
    param([Parameter(Mandatory = $true)][string]$Root)
    foreach ($file in Get-ChildItem -Path $Root -Recurse -Filter *.ps1) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        $hits = $ast.FindAll({
                param($n)
                ($n -is [System.Management.Automation.Language.CommandAst]) -or
                ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $script:IgwtStateMembers -contains $n.Member.Value)
            }, $true)
        foreach ($h in $hits) {
            $cmd = $null
            if ($h -is [System.Management.Automation.Language.CommandAst]) {
                $name = $h.GetCommandName()
                if (-not $name) { continue }
                $base = ([System.IO.Path]::GetFileNameWithoutExtension($name)).ToLowerInvariant()
                if ($script:IgwtStateCmdlets -contains $name) { $cmd = $name }
                elseif ($script:IgwtStateWrappers.Contains($name)) {
                    $rx = $script:IgwtStateWrappers[$name]
                    if (-not $rx -or $h.Extent.Text -match $rx) { $cmd = $name }
                }
                elseif ($script:IgwtStateTools.Contains($base) -and ($name -match '\.exe$' -or $base -eq $name.ToLowerInvariant())) {
                    $argText = @($h.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text.Trim("'", '"') }) -join ' '
                    $rx = $script:IgwtStateTools[$base]
                    if (-not $rx -or $argText -match $rx -or $argText -match '^\$|^@') { $cmd = "$base $argText".Trim() }
                } elseif ($name -in 'New-Item', 'Remove-Item' -and $h.Extent.Text -match 'HK(LM|CU|U|CR)[:\\]|Registry::|\$(reg|key|path)') {
                    # Registry paths only (file writes of the tool's own data are not system state).
                    if ($h.Extent.Text -match 'HK(LM|CU|U|CR)[:\\]|Registry::') { $cmd = "$name (registry)" }
                }
            } else { $cmd = ".$($h.Member.Value)()" }
            if (-not $cmd) { continue }
            $fn = $h.Parent
            while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
            [pscustomobject]@{ File = $file.FullName.Substring($Root.Length).TrimStart('\'); Function = $(if ($fn) { $fn.Name } else { '<script>' }); Line = $h.Extent.StartLineNumber; Command = $cmd }
        }
    }
}

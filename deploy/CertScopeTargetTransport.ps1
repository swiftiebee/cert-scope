function Get-LocalReader([string]$Account, [switch]$Undo) {
    $parts = $Account.Trim().Split('\')
    if ($parts.Count -gt 2 -or ($parts.Count -eq 2 -and $parts[0] -ne $env:COMPUTERNAME) -or -not $parts[-1]) {
        throw "Specify a local user on $env:COMPUTERNAME."
    }
    $user = Get-LocalUser | Where-Object { $_.Name -eq $parts[-1] }
    if (-not $user) { throw "Local account not found: $($parts[-1])" }
    if (-not $Undo -and -not $user.Enabled) { throw "Local user is disabled: $($user.Name)" }
    return $user
}

function Get-TargetTransport([string]$ClientIPv4, [string]$Profile, [switch]$Undo) {
    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($ClientIPv4, [ref]$address) -or
        $address.AddressFamily -ne 'InterNetwork' -or $address.ToString() -cne $ClientIPv4) {
        throw 'Specify one IPv4 address in dotted decimal form.'
    }
    $bytes = $address.GetAddressBytes()
    if ($bytes[0] -ne 10 -and ($bytes[0] -ne 172 -or $bytes[1] -notin (16..31)) -and
        ($bytes[0] -ne 192 -or $bytes[1] -ne 168)) {
        throw 'Specify the private IPv4 address of the scanner (10/8, 172.16/12 or 192.168/16).'
    }
    if ($Undo) { return }

    $computer = Get-CimInstance Win32_ComputerSystem
    if (($Profile -eq 'Domain') -ne $computer.PartOfDomain -or $computer.DomainRole -ge 4) {
        throw 'Use Workgroup on a standalone target or Domain on an already domain-joined member PC.'
    }
    if (Get-NetIPAddress -IPAddress $ClientIPv4 -AddressFamily IPv4 -ErrorAction SilentlyContinue) {
        throw 'Provide the IP of the scanner, not this target.'
    }
    $route = Find-NetRoute -RemoteIPAddress $ClientIPv4 | Where-Object IPAddress | Select-Object -First 1
    if (-not $route) { throw "No local route to $ClientIPv4." }
    $category = if ($Profile -eq 'Domain') { 'DomainAuthenticated' } else { 'Private' }
    $network = Get-NetConnectionProfile -InterfaceIndex $route.InterfaceIndex
    if (-not $network -or $network.NetworkCategory -ne $category) {
        throw "Network interface '$($route.InterfaceAlias)' must use the $category network category."
    }
    if ((Get-Service -Name LanmanServer).Status -ne 'Running') {
        throw 'The Windows Server (LanmanServer) service must be running to accept SMB connections.'
    }
    return $route.IPAddress
}

function New-TransportBackup([string]$ClientIPv4, [string]$Profile) {
    $service = Get-Service -Name RemoteRegistry
    if ($service.Status -notin 'Running', 'Stopped' -or $service.StartType -notin 'Automatic', 'Manual', 'Disabled') {
        throw 'Remote Registry is changing state. Wait, then run setup again.'
    }
    return [pscustomobject]@{
        Rule = 'CertScope-SMB-' + [guid]::NewGuid().ToString('N')
        ClientIPv4 = $ClientIPv4
        Profile = $Profile
        ServiceStatus = [string]$service.Status
        ServiceStart = [string]$service.StartType
    }
}

function Assert-TransportBackup($Transport, [string]$ClientIPv4, [string]$Profile) {
    if (-not $Transport -or $Transport.ClientIPv4 -cne $ClientIPv4 -or $Transport.Profile -ne $Profile -or
        $Transport.Rule -notmatch '^CertScope-SMB-[0-9a-f]{32}$' -or
        $Transport.ServiceStatus -notin 'Running', 'Stopped' -or
        $Transport.ServiceStart -notin 'Automatic', 'Manual', 'Disabled') {
        throw 'Existing target setup is for different inputs or is incomplete. Use the original inputs with -Undo.'
    }
}

function Get-SetupFirewallRule($Transport) {
    $rule = Get-NetFirewallRule -Name $Transport.Rule -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    if ($rule) {
        $addresses = $rule | Get-NetFirewallAddressFilter
        $ports = $rule | Get-NetFirewallPortFilter
        if ($rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or $rule.Profile -ne $Transport.Profile -or
            $rule.Enabled -ne 'True' -or @($addresses.RemoteAddress).Count -ne 1 -or
            @($addresses.RemoteAddress)[0] -ne $Transport.ClientIPv4 -or
            $ports.Protocol -notin 'TCP', '6' -or $ports.LocalPort -ne '445') {
            throw "Firewall rule was edited outside setup: $($Transport.Rule)."
        }
    }
    return $rule
}

function Set-TargetTransport($Transport) {
    $service = Get-Service -Name RemoteRegistry
    if ($service.StartType -ne 'Automatic' -and $service.StartType -ne $Transport.ServiceStart) {
        throw 'Remote Registry startup type changed outside setup.'
    }
    if (-not (Get-SetupFirewallRule $Transport)) {
        $ruleParameters = @{
            Name = $Transport.Rule
            DisplayName = "CertScope TCP 445 from $($Transport.ClientIPv4)"
            PolicyStore = 'PersistentStore'
            Direction = 'Inbound'
            Action = 'Allow'
            Protocol = 'TCP'
            LocalPort = 445
            RemoteAddress = $Transport.ClientIPv4
            Profile = $Transport.Profile
            EdgeTraversalPolicy = 'Block'
        }
        New-NetFirewallRule @ruleParameters -Confirm:$false | Out-Null
    }
    if ($service.StartType -ne 'Automatic') {
        Set-Service -Name RemoteRegistry -StartupType Automatic -Confirm:$false
    }
    if ($service.Status -ne 'Running') {
        Start-Service -Name RemoteRegistry -Confirm:$false
    }
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
}

function Restore-TargetTransport($Transport) {
    $rule = Get-SetupFirewallRule $Transport
    $service = Get-Service -Name RemoteRegistry
    if ($service.StartType -ne 'Automatic' -and $service.StartType -ne $Transport.ServiceStart) {
        throw 'Remote Registry startup type changed outside setup.'
    }
    if ($rule) {
        Remove-NetFirewallRule -Name $Transport.Rule -PolicyStore PersistentStore -Confirm:$false
    }
    if ($Transport.ServiceStatus -eq 'Stopped' -and $service.Status -ne 'Stopped') {
        Stop-Service -Name RemoteRegistry -Confirm:$false
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    if ($service.StartType -ne $Transport.ServiceStart) {
        Set-Service -Name RemoteRegistry -StartupType $Transport.ServiceStart -Confirm:$false
    }
}

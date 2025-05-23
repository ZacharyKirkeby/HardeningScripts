function Section($t) { "`n### $t ###" }

Section "Interface IP / Gateway / DNS"
$iface = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway }
"Interface : $($iface.InterfaceAlias)"
"IP        : $($iface.IPv4Address.IPAddress)"
"Gateway   : $($iface.IPv4DefaultGateway.NextHop)"
"DNS       : $($iface.DNSServer.ServerAddresses -join ', ')"

Section "Default Route(s)"
Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
    Select-Object NextHop, InterfaceAlias, RouteMetric |
    Format-Table -AutoSize

Section "Established Connections"
Get-NetTCPConnection -State Established |
    Where-Object { $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' } |
    Sort-Object RemoteAddress -Unique |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $hostname = try {
            [System.Net.Dns]::GetHostEntry($_.RemoteAddress).HostName
        } catch {
            $null
        }
        [PSCustomObject]@{
            RemoteAddress = $_.RemoteAddress
            Hostname      = $hostname
            RemotePort    = $_.RemotePort
            Process       = $proc.ProcessName
        }
    } | Format-Table -AutoSize

Section "TCP Ports"
Get-NetTCPConnection -State Listen | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalPort = $_.LocalPort
        Process   = $proc.ProcessName
    }
} | Sort-Object LocalPort | Format-Table -AutoSize

Section "Reachable Devices"
Get-NetNeighbor -AddressFamily IPv4 |
    Where-Object { $_.State -eq 'Reachable' } |
    Select-Object IPAddress, LinkLayerAddress |
    Format-Table -AutoSize

Section "SMB Shares"
Get-SmbShare | Where-Object { $_.Name -notin @('IPC$', 'ADMIN$') } |
    Select-Object Name, Path | Format-Table -AutoSize

if (netsh wlan show interfaces 2>$null) {
    Section "Wi-Fi Network Info"
    netsh wlan show interfaces | ForEach-Object {
        if ($_ -match '^\s*SSID|Signal|BSSID|Radio type|Channel') {
            $_.Trim()
        }
    }
}
Section "Live Hosts"
$localIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.PrefixOrigin -ne 'WellKnown' }).IPAddress[0]
$subnet = ($localIP -replace '\d+$','')
1..254 | ForEach-Object {
    $target = "$subnet$_"
    if (Test-Connection -Count 1 -Quiet -ComputerName $target) {
        "$target"
    }
}

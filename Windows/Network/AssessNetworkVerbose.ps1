"=== Network Interfaces ==="
Get-NetIPConfiguration | Format-List
"=== DNS Client Settings ==="
Get-DnsClient | Format-List
"=== DNS Server Addresses ==="
Get-DnsClientServerAddress | Format-List
"=== Routing Table ==="
Get-NetRoute | Sort-Object -Property RouteMetric | Format-Table
"=== ARP Cache ==="
Get-NetNeighbor | Format-Table
"=== Active TCP Connections ==="
Get-NetTCPConnection | Format-Table
"=== Listening Ports ==="
Get-NetTCPConnection -State Listen | Format-Table
"=== UDP Endpoints ==="
Get-NetUDPEndpoint | Format-Table
"=== Local Shared Resources ==="
Get-SmbShare | Format-Table
"=== Network Adapter Details ==="
Get-NetAdapter | Format-List
"=== Reverse DNS for Active Connections ==="
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | 
    ForEach-Object {
        try {
            [System.Net.Dns]::GetHostEntry($_.RemoteAddress)
        } catch {}
    }
"=== Wireless Network Info ==="
if (Get-Command -Name netsh -ErrorAction SilentlyContinue) {
    netsh wlan show interfaces
    netsh wlan show profiles
}
"=== Live Hosts on Local Subnet ==="
$localIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '169.*' -and $_.PrefixOrigin -ne 'WellKnown' }
).IPAddress[0]
$subnet = ($localIP -replace '\d+$','')
1..254 | ForEach-Object {
    $target = "$subnet$_"
    if (Test-Connection -Count 1 -Quiet -ComputerName $target) {
        "$target is alive"
    }
}
"=== NetBIOS Name Discovery ==="
$ips = 1..254 | ForEach-Object { "$subnet$_" }
foreach ($ip in $ips) {
    try {
        $name = [System.Net.Dns]::GetHostEntry($ip).HostName
        "$ip -> $name"
    } catch {}
}

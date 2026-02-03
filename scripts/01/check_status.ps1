Write-Host "Hostname: $env:COMPUTERNAME"

$IP = Get-NetIPAddress -AddressFamily IPv4 |
      Where-Object { $_.IPAddress -ne "127.0.0.1" } |
      Select-Object -First 1 -ExpandProperty IPAddress

if ($IP) {
    Write-Host "IP actual: $IP"
} else {
    Write-Host "IP actual: No asignada"
}

Write-Host "Uso de disco:"

Get-PSDrive -PSProvider FileSystem |
    Where-Object { $_.Name -eq "C" } |
    Select-Object Name,
                  @{Name="Usado(GB)";Expression={[math]::Round($_.Used/1GB,2)}},
                  @{Name="Libre(GB)";Expression={[math]::Round($_.Free/1GB,2)}}
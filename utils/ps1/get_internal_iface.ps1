
[CmdletBinding()]
param ()

$defaultRoutes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
$internetIfaceIndices = @()
if ($defaultRoutes) {
    $internetIfaceIndices = @($defaultRoutes | Select-Object -ExpandProperty InterfaceIndex)
}

$adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false -and $_.Name -notmatch "vEthernet|Default Switch|Loopback" })

$internalAdapters = @()
if ($internetIfaceIndices.Count -gt 0) {
    $internalAdapters = @($adapters | Where-Object { $internetIfaceIndices -notcontains $_.InterfaceIndex })
}

$ActiveIface = $null

if ($internalAdapters.Count -gt 0) {
    $ActiveIface = $internalAdapters[0]
} else {
    if ($adapters.Count -gt 1) {
        $ActiveIface = $adapters[0]
    } elseif ($adapters.Count -eq 1) {
        $ActiveIface = $adapters[0]
    }
}

if ($ActiveIface) {
    Write-Output $ActiveIface.Name
}

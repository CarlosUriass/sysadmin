<#
.SYNOPSIS
Configura una direccion IP estática para una interfaz de red especifica.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$InterfaceName,

    [Parameter(Mandatory=$true)]
    [string]$IP,

    [Parameter(Mandatory=$true)]
    [int]$PrefixLength
)

$iface = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
if (-not $iface -and $InterfaceName -match '^\d+$') {
    $iface = Get-NetAdapter -InterfaceIndex ([int]$InterfaceName) -ErrorAction SilentlyContinue
}
if (-not $iface) {
    Write-Error "No se encontró la interfaz de red '$InterfaceName' (ni por Alias ni por Índice)."
    return
}
$Alias = $iface.Name

Write-Host "Cambiando IP de la interfaz '$Alias' a $IP/$PrefixLength..."

Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

Get-NetRoute -InterfaceAlias $Alias -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceAlias $Alias -IPAddress $IP -PrefixLength $PrefixLength -ErrorAction Stop | Out-Null
Write-Host "IP migrada exitosamente a $IP"

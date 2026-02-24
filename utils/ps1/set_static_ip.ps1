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

Write-Host "cambiando ip de $InterfaceName a $IP/$PrefixLength..."

Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

Get-NetRoute -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceAlias $InterfaceName -IPAddress $IP -PrefixLength $PrefixLength -ErrorAction Stop | Out-Null
Write-Host "ip cambiada a $IP"

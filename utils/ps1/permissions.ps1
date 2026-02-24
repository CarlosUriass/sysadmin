[CmdletBinding()]
param (
    [switch]$CheckAdmin,
    [switch]$Help
)

if ($Help) {
    Write-Host "Uso: .\permissions.ps1 -CheckAdmin"
    exit 0
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: ejecutar como administrador"
    exit 1
}

exit 0

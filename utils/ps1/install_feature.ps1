<#
.SYNOPSIS
Instala un rol o caracteristica de Windows desde la fuente WIM correcta.
.DESCRIPTION
Usa el archivo install.wim del disco de instalacion como fuente para evitar errores de red o ausencia de SxS.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$FeatureName,

    [switch]$IncludeAllSubFeature,

    [string]$WimPath = "D:\sources\install.wim",

    [int]$WimIndex = 2,

    [switch]$Help
)

if ($Help) {
    Write-Host "Uso: .\install_feature.ps1 -FeatureName <nombre> [-IncludeAllSubFeature] [-WimPath <ruta>] [-WimIndex <n>]"
    exit 0
}

$feature = Get-WindowsFeature -Name $FeatureName -ErrorAction SilentlyContinue

if ($feature -and $feature.Installed) {
    Write-Host "ok: $FeatureName ya instalado"
    exit 0
}

Write-Host "info: instalando $FeatureName desde $WimPath`:$WimIndex ..."

$source = "wim:${WimPath}:${WimIndex}"
$params = @{
    Name                  = $FeatureName
    IncludeManagementTools = $true
    Source                = $source
    ErrorAction           = 'Stop'
}

if ($IncludeAllSubFeature) {
    $params['IncludeAllSubFeature'] = $true
}

Install-WindowsFeature @params | Out-Null
Write-Host "ok: $FeatureName instalado"

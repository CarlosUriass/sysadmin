<#
.SYNOPSIS
Activa la regla del Firewall de Windows para permitir respuestas de Ping (ICMPv4 Echo Request).
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Write-Host "Configurando el Firewall de Windows para permitir Ping (ICMPv4)..." -ForegroundColor Cyan

# 1. Intentar primero habilitar las reglas nativas (las que vienen puestas por Microsoft pero apagadas)
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -ErrorAction SilentlyContinue

# 2. De forma paralela, crear una regla explícita dedicada (Por si la regla nativa está rota o el idioma de Windows impide encontrarla)
$ruleName = "Allow-Ping-ICMPv4-In"
$exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

if (-not $exists) {
    New-NetFirewallRule -DisplayName $ruleName `
                        -Description "Permite peticiones de eco (Ping) desde cualquier origen." `
                        -Direction Inbound `
                        -Protocol ICMPv4 `
                        -IcmpType 8 `
                        -Action Allow `
                        -Profile Any | Out-Null
    Write-Host "[OK] Nueva regla '$ruleName' agregada exitosamente." -ForegroundColor Green
} else {
    Set-NetFirewallRule -DisplayName $ruleName -Enabled True -Action Allow
    Write-Host "[OK] La regla '$ruleName' ya estaba agregada y ahora se garantizó que esté activa." -ForegroundColor Green
}

Write-Host "Tu servidor Windows ahora responderá a las peticiones PING." -ForegroundColor Green

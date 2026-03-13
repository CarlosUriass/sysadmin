# ==============================================================================
# Script: test_http_deploy.ps1
# description: Prueba de despliegue automatizado para Practica 6 (Windows)
# ==============================================================================

$Script = ".\http_deploy.ps1"
$Services = @("iis", "apache", "nginx")
$BasePort = 3020

Write-Host "=== INICIANDO PRUEBAS DE DESPLIEGUE (WINDOWS) ===" -ForegroundColor Cyan

# 1. Limpieza inicial
Write-Host "[1/3] Limpiando sistema..." -ForegroundColor Yellow
& $Script -Purge | Out-Null

# 2. Iterar servicios
for ($i=0; $i -lt $Services.Count; $i++) {
    $Srv = $Services[$i]
    $Port = $BasePort + $i
    
    Write-Host "------------------------------------------------"
    Write-Host "Probando servicio: $Srv en puerto $Port..." -ForegroundColor Cyan
    
    try {
        & $Script -Service $Srv -Port $Port
        Write-LogSuccess "Instalacion exitosa."
        
        # Verificar con IWR
        $Resp = Invoke-WebRequest -Uri "http://localhost:$Port" -UseBasicParsing
        if ($Resp.Content -match "Servidor: $Srv") {
            Write-Host "VERIFICACION: OK (Contenido index.html correcto)" -ForegroundColor Green
        } else {
            Write-Host "VERIFICACION: FAIL (Contenido incorrecto)" -ForegroundColor Red
        }
        
        if ($Resp.Headers['X-Frame-Options'] -eq "SAMEORIGIN") {
            Write-Host "SECURITY: OK (Headers presentes)" -ForegroundColor Green
        } else {
            Write-Host "SECURITY: FAIL (Headers faltantes)" -ForegroundColor Red
        }
    } catch {
        Write-Host "RESULTADO: FALLO en $Srv - $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Write-LogSuccess($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }

Write-Host "=== PRUEBAS FINALIZADAS ===" -ForegroundColor Cyan

# Script de respaldo para el servidor de correo (volumen mail_data) para Windows
# Este script comprime el contenido de los buzones usando un contenedor temporal.

$BackupDir = ".\backups"
$DateStr = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFile = "mail_data_backup_$DateStr.tar.gz"

if (!(Test-Path -Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir | Out-Null
}

Write-Host "[*] Iniciando respaldo del volumen de correos (mail_data)..."

# Convertir ruta relativa a absoluta para mapeo de Docker en Windows
$AbsoluteBackupDir = Convert-Path $BackupDir
$AbsoluteBackupDir = $AbsoluteBackupDir -replace '\\', '/'

# Ejecutar el contenedor de Alpine para comprimir el volumen
docker run --rm `
    -v mailserver_mail_data:/var/mail `
    -v "${AbsoluteBackupDir}:/backup" `
    alpine tar czf "/backup/$BackupFile" -C /var/mail .

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Respaldo completado exitosamente: $BackupDir\$BackupFile" -ForegroundColor Green
    Write-Host "[*] Este script puede ser programado usando el Programador de Tareas de Windows." -ForegroundColor Cyan
} else {
    Write-Host "[-] Error al realizar el respaldo." -ForegroundColor Red
    exit 1
}

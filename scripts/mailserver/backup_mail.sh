#!/bin/bash
# Script de respaldo para el servidor de correo (volumen mail_data)
# Este script comprime el contenido de los buzones cada 24 hrs.

BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="mail_data_backup_$DATE.tar.gz"

# Crear directorio de respaldos si no existe
mkdir -p "$BACKUP_DIR"

echo "[*] Iniciando respaldo del volumen de correos (mail_data)..."

# NOTA: El prefijo 'mailserver_' asume que el nombre del directorio es 'mailserver'.
# Si Docker Compose nombra el volumen diferente, debes ajustar 'mailserver_mail_data'.
docker run --rm \
    -v mailserver_mail_data:/var/mail \
    -v $(pwd)/$BACKUP_DIR:/backup \
    alpine tar czf /backup/$BACKUP_FILE -C /var/mail .

if [ $? -eq 0 ]; then
    echo "[+] Respaldo completado exitosamente: $BACKUP_DIR/$BACKUP_FILE"
    echo "[*] Este script debe ser programado en cron (ej. 0 2 * * * /ruta/a/backup_mail.sh)"
else
    echo "[-] Error al realizar el respaldo."
    exit 1
fi

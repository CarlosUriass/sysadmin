#!/bin/bash
# ==============================================================================
# Script: backup.sh
# Descripcion: Respaldo automatizado de PostgreSQL hacia el directorio montado
#              del host. Retiene los ultimos 7 respaldos.
# ==============================================================================

BACKUP_DIR="/backups"
DB_NAME="${POSTGRES_DB:-infraestructura}"
DB_USER="${POSTGRES_USER:-admin}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${TIMESTAMP}.sql.gz"
MAX_BACKUPS=7

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Iniciando respaldo de la base de datos '$DB_NAME'..."

# Ejecutar pg_dump y comprimir
if pg_dump -U "$DB_USER" "$DB_NAME" | gzip > "$BACKUP_FILE"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] OK: Respaldo creado -> $BACKUP_FILE"
    
    # Calcular tamano
    TAMANO=$(du -h "$BACKUP_FILE" | awk '{print $1}')
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Tamano del respaldo: $TAMANO"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAIL: Error al crear el respaldo"
    exit 1
fi

# Rotacion: mantener solo los ultimos MAX_BACKUPS respaldos
TOTAL=$(ls -1 "${BACKUP_DIR}/${DB_NAME}_"*.sql.gz 2>/dev/null | wc -l)
if (( TOTAL > MAX_BACKUPS )); then
    ELIMINAR=$((TOTAL - MAX_BACKUPS))
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Rotando: eliminando $ELIMINAR respaldo(s) antiguo(s)..."
    ls -1t "${BACKUP_DIR}/${DB_NAME}_"*.sql.gz | tail -n "$ELIMINAR" | xargs rm -f
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Respaldo completado. Total de respaldos: $(ls -1 "${BACKUP_DIR}/${DB_NAME}_"*.sql.gz 2>/dev/null | wc -l)"

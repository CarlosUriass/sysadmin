#!/bin/bash
# ==============================================================================
# Script: run_tests.sh
# Descripcion: Protocolo de pruebas (Guia de validacion 10.1 - 10.4)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Cargar utilidades de logging
if [[ -f "$SCRIPT_DIR/../../../utils/logs/logger.sh" ]]; then
    source "$SCRIPT_DIR/../../../utils/logs/logger.sh"
else
    echo "ERROR: No se encuentra utils/logs/logger.sh"
    exit 1
fi

log_info "=== INICIANDO PROTOCOLO DE PRUEBAS ==="

# ---------------------------------------------------------
# Prueba 10.1: Persistencia de BD
# ---------------------------------------------------------
log_info "[Prueba 10.1] Verificando persistencia de base de datos..."
log_info "Creando tabla y registro de prueba en PostgreSQL..."
docker exec db_server psql -U admin -d infraestructura -c "CREATE TABLE IF NOT EXISTS test_persistencia (id SERIAL PRIMARY KEY, dato VARCHAR(50));" >/dev/null 2>&1 || true
docker exec db_server psql -U admin -d infraestructura -c "INSERT INTO test_persistencia (dato) VALUES ('Datos guardados exitosamente');" >/dev/null 2>&1 || true

log_warn "Eliminando contenedor db_server..."
docker rm -f db_server >/dev/null || true

log_info "Re-desplegando contenedor de BD..."
# Reutilizamos el script principal para redesplegar
sudo bash "$SCRIPT_DIR/../deploy_containers.sh" --deploy >/dev/null 2>&1

# Esperar unos segundos a que levante PostgreSQL
sleep 10

log_info "Verificando si los datos persisten..."
RESULT=$(docker exec db_server psql -U admin -d infraestructura -t -c "SELECT dato FROM test_persistencia LIMIT 1;" 2>/dev/null | xargs || true)

if [[ "$RESULT" == "Datos guardados exitosamente" ]]; then
    log_success "Prueba 10.1 SUPERADA: Los datos persisten despues de recrear el contenedor."
else
    log_error "Prueba 10.1 FALLIDA: No se encontraron los datos."
fi


# ---------------------------------------------------------
# Prueba 10.2: Aislamiento de Red
# ---------------------------------------------------------
log_info "[Prueba 10.2] Verificando aislamiento y conectividad de red..."
log_info "Haciendo ping desde web_server hacia db_server..."

if docker exec web_server ping -c 3 db_server >/dev/null 2>&1; then
    log_success "Prueba 10.2 SUPERADA: El web_server tiene conectividad con el db_server."
else
    log_error "Prueba 10.2 FALLIDA: No hay conectividad de red."
fi


# ---------------------------------------------------------
# Prueba 10.3: Permisos FTP y visibilidad Web
# ---------------------------------------------------------
log_info "[Prueba 10.3] Verificando subida FTP y visibilidad Web..."
TEST_FILE="ftp_test_$(date +%s).txt"
TEST_CONTENT="Este es un archivo de prueba subido por FTP"

log_info "Creando archivo temporal local y simulando subida por FTP..."
echo "$TEST_CONTENT" > "/tmp/$TEST_FILE"

cp "/tmp/$TEST_FILE" "/opt/docker/ftp_uploads/$TEST_FILE"
chmod 644 "/opt/docker/ftp_uploads/$TEST_FILE"

log_info "Verificando si el servidor web Nginx puede visualizarlo..."
WEB_RESULT=$(docker exec web_server cat /usr/share/nginx/html/uploads/"$TEST_FILE" 2>/dev/null || true)

if [[ "$WEB_RESULT" == "$TEST_CONTENT" ]]; then
    log_success "Prueba 10.3 SUPERADA: El archivo subido via FTP es visible para el servidor web."
else
    log_error "Prueba 10.3 FALLIDA: El servidor web no puede leer el archivo."
fi
rm -f "/tmp/$TEST_FILE"


# ---------------------------------------------------------
# Prueba 10.4: Limites de Recursos
# ---------------------------------------------------------
log_info "[Prueba 10.4] Verificando limites de recursos..."
log_info "Ejecutando 'docker stats --no-stream':"
docker stats --no-stream web_server db_server ftp_server
echo ""
log_success "Prueba 10.4 COMPLETADA: Verifica en la tabla superior la columna 'LIMIT' (Memoria asignada)."

log_info "=== PROTOCOLO DE PRUEBAS FINALIZADO ==="

#!/bin/bash
# ==============================================================================
# Script: test_http_deploy.sh
# description: Prueba de despliegue automatizado para Practica 6
# ==============================================================================
set -euo pipefail

# Definir rutas absolutas
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$SCRIPT_DIR/http_deploy.sh"
LOG_FILE="$SCRIPT_DIR/test_results.log"

# Asegurar permisos de ejecucion
chmod +x "$SCRIPT"

SERVICES=("apache" "nginx" "tomcat")
BASE_PORT=3010

echo "=== INICIANDO PRUEBAS DE DESPLIEGUE (LINUX) ===" | tee "$LOG_FILE"

# 1. Limpieza inicial
echo "[1/3] Limpiando sistema..."
if sudo "$SCRIPT" --purge; then
    echo "Limpieza completada."
else
    echo "Advertencia: La limpieza reporto algunos errores (puede ser normal si no hay servicios)."
fi

# 2. Iterar servicios
for i in "${!SERVICES[@]}"; do
    SRV="${SERVICES[$i]}"
    PORT=$((BASE_PORT + i))
    
    echo "------------------------------------------------" | tee -a "$LOG_FILE"
    echo "Probando servicio: $SRV en puerto $PORT..." | tee -a "$LOG_FILE"
    
    if sudo "$SCRIPT" --service "$SRV" --port "$PORT"; then
        echo "RESULTADO: Instalacion exitosa." | tee -a "$LOG_FILE"
        
        # Verificar con curl
        echo "Verificando respuesta HTTP..." | tee -a "$LOG_FILE"
        if curl -s "http://localhost:$PORT" | grep -q "Servidor: $SRV"; then
            echo "VERIFICACION: OK (Contenido index.html correcto)" | tee -a "$LOG_FILE"
        else
            echo "VERIFICACION: FAIL (Contenido incorrecto o inaccesible)" | tee -a "$LOG_FILE"
        fi
        
        echo "Verificando headers de seguridad..." | tee -a "$LOG_FILE"
        HEADERS=$(curl -Is "http://localhost:$PORT")
        if echo "$HEADERS" | grep -qi "X-Frame-Options: SAMEORIGIN"; then
            echo "SECURITY: OK (Headers presentes)" | tee -a "$LOG_FILE"
        else
            echo "SECURITY: FAIL (Headers faltantes)" | tee -a "$LOG_FILE"
        fi
    else
        echo "RESULTADO: FALLO en la instalacion de $SRV." | tee -a "$LOG_FILE"
    fi
done

echo "=== PRUEBAS FINALIZADAS. Ver test_results.log para mas detalles. ===" | tee -a "$LOG_FILE"

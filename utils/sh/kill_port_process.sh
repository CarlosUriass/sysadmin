#!/bin/bash

# Script para matar el proceso asociado a un puerto

# Importar funciones de log
source "$(dirname "$0")/../logs/logger.sh"

PORT=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --port|-port|-p)
            PORT="$2"
            shift
            ;;
        -h|--help)
            echo "Uso: $0 --port <numero_puerto>"
            exit 0
            ;;
        *)
            echo "Parámetro desconocido: $1. Use --help para ayuda."
            exit 1
            ;;
    esac
    shift
done

if [[ -z "$PORT" ]]; then
    log_error "Falta el parámetro --port."
fi

# Buscar PIDs en ESTADO LISTEN primero
PIDS=$(lsof -Pi :"$PORT" -sTCP:LISTEN -t)

# Si no hay ninguno en estado listen, buscar cualquier proceso en ese puerto
if [[ -z "$PIDS" ]]; then
    PIDS=$(lsof -Pi :"$PORT" -t)
fi

if [[ -n "$PIDS" ]]; then
    # lsof retorna los ids de los procesos, pueden ser varios
    log_info "Identificados procesos en puerto $PORT. Deteniendo (PIDs: $(echo $PIDS | tr '\n' ' '))..."
    # Usamos kill -9 para forzar la detencion (sigkill)
    kill -9 $PIDS
    log_success "Procesos detenidos con éxito."
    exit 0
else
    log_info "No se encontraron procesos usando el puerto $PORT."
    exit 1
fi

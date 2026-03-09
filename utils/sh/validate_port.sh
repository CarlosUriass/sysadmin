#!/bin/bash

# Función para verificar que un puerto sea válido y no reservado
source "$(dirname "$0")/../logs/logger.sh"

validate_port() {
    local port="$1"
    
    # Verificar que el puerto sea un número válido
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then 
        return 1 
    fi

    # Verificar que esté en el rango 1-65535
    if (( port < 1 || port > 65535 )); then 
        return 1 
    fi

    # Verificar que no sea un puerto reservado (1-1023)
    if (( port >= 1 && port <= 1023 )); then 
        return 1 
    fi

    return 0
}

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
            echo "Parametro desconocido: $1. Use --help para ayuda."
            exit 1
            ;;
    esac
    shift
done

if [[ -z "$PORT" ]]; then
    log_error "Falta el parametro --port."
fi

if validate_port "$PORT"; then
    log_success "El puerto $PORT es válido."
    exit 0
else
    log_error "El puerto $PORT es inválido o se trata de un puerto reservado (1-1023)."
fi

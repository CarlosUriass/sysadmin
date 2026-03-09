#!/bin/bash

# Script para verificar si un puerto está en uso

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
    echo "Error: Falta el parámetro --port."
    exit 1
fi

# lsof -Pi :<puerto> -sTCP:LISTEN -t retorna solo el PID de manera silenciosa
# Para ampliar compatibilidad buscamos cualquier uso de ese puerto si no hay LISTEN
if lsof -Pi :"$PORT" -sTCP:LISTEN -t >/dev/null 2>&1 || lsof -Pi :"$PORT" -t >/dev/null 2>&1; then
    echo "El puerto $PORT está en uso."
    exit 0
else
    echo "El puerto $PORT no está en uso."
    exit 1
fi

#!/bin/bash

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        return 1
    fi
    return 0
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --check-root|-c)
            # just consumes flag
            ;;
        -h|--help)
            echo "Uso: $0 [--check-root]"
            exit 0
            ;;
        *)
            echo "Parametro desconocido: $1. Use --help para ayuda."
            exit 1
            ;;
    esac
    shift
done

if check_root; then
    exit 0
else
    echo "Privilegios insuficientes. Ejecute como root (sudo)."
    exit 1
fi

#!/bin/bash
# ==============================================================================
# Script: install_package.sh
# description: Instala paquetes via apt-get de forma idempotente
# ==============================================================================

PACKAGES=()

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -p|--packages)
            shift
            while [[ "$#" -gt 0 && "$1" != -* ]]; do
                PACKAGES+=("$1")
                shift
            done
            ;;
        -h|--help)
            echo "Uso: $0 -p <paquete1> [paquete2 ...]"
            exit 0
            ;;
        *)
            echo "Parametro desconocido: $1"; exit 1 ;;
    esac
done

if [[ ${#PACKAGES[@]} -eq 0 ]]; then
    echo "Error: debes especificar al menos un paquete con -p"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo "ok: $pkg ya instalado"
    else
        echo "info: instalando $pkg ..."
        apt-get update -qq
        if apt-get install -y -qq "$pkg"; then
            if dpkg -s "$pkg" &>/dev/null; then
                echo "ok: $pkg instalado"
            else
                echo "FAIL: $pkg no se pudo verificar tras la instalacion"
                exit 1
            fi
        else
            echo "FAIL: error al instalar $pkg"
            exit 1
        fi
    fi
done

#!/bin/bash


validate_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then return 1; fi
    IFS='.' read -r -a octet <<< "$ip"
    for i in "${octet[@]}"; do
        if (( i > 255 )); then return 1; fi
    done
    return 0
}

IP=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --ip|-ip|-i)
            IP="$2"
            shift
            ;;
        -h|--help)
            echo "Uso: $0 --ip <direccion_ip>"
            exit 0
            ;;
        *)
            echo "Parametro desconocido: $1. Use --help para ayuda."
            exit 1
            ;;
    esac
    shift
done

if [[ -z "$IP" ]]; then
    echo "Error: Falta el parametro --ip."
    exit 1
fi

if validate_ipv4 "$IP"; then
    exit 0
else
    exit 1
fi

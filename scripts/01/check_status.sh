#!/bin/bash

echo
echo "--- Estado del sistema ---"

HOSTNAME=$(hostname)
echo "Nombre de la maquina: $HOSTNAME"

IP=$(hostname -I | awk '{print $1}')

if [ -z "$IP" ]; then
    echo "IP actual: No asignada"
else
    echo "IP actual: $IP"
fi

echo
echo "Uso de disco:"
# Corregido 'dt-h11' por 'df -h'
df -h | awk 'NR==1 || NR==2'
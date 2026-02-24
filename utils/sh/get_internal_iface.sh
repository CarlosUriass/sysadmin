#!/bin/bash

# Detectar la interfaz por defecto de internet
default_iface=$(ip route | awk '/default/ {print $5}' | head -1)

# Listar interfaces, quitar loopback y la default, tomar la primera disponible
internal_iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE "^lo$|^$default_iface$" | head -1)

if [[ -z "$internal_iface" ]]; then 
    # Fallback estricto a la 3ra interfaz (Usualmente enp0s8 en VirtualBox)
    internal_iface=$(ip -o link show | awk -F': ' '{print $2}' | sed -n '3p')
fi

echo "$internal_iface"

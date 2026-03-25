#!/bin/bash

IFACE=""
IP=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -i|--iface) IFACE="$2"; shift ;;
        -ip|--ip) IP="$2"; shift ;;
        -h|--help)
            echo "Uso: $0 -i <interfaz> -ip <ip_con_prefijo>"
            exit 0
            ;;
        *) echo "Parametro desconocido: $1"; exit 1 ;;
    esac
    shift
done

if [[ $EUID -ne 0 ]]; then
   echo "ERROR: Este script debe ejecutarse como root (usa sudo)."
   exit 1
fi

if [[ -z "$IFACE" || -z "$IP" ]]; then
    echo "Faltan parametros. Uso: $0 -i <interfaz> -ip <ip/mascara>"
    exit 1
fi

echo "Cambiando IP de $IFACE a $IP ..."

ip addr flush dev "$IFACE" || echo "Aviso: no se pudo limpiar la interfaz"
ip addr add "$IP" dev "$IFACE"
ip link set "$IFACE" up

NETPLAN_DIR="/etc/netplan"
if [[ -d "$NETPLAN_DIR" ]]; then
    netplan_file=$(find "$NETPLAN_DIR" -name "*.yaml" -type f | head -1)
    if [[ -n "$netplan_file" ]]; then
        # Extraer el renderer original (si existía) para evitar conflictos con NetworkManager/networkd
        render_line=$(grep -i "renderer:" "$netplan_file" | head -1)
        
        cp "$netplan_file" "${netplan_file}.bak.$(date +%s)"
        
        # Obtener default_iface. Si está vacía o es la que vamos a editar, no la ponemos duplicada
        default_iface=$(ip route | awk '/default/ {print $5}' | head -1)
        
        cat > "$netplan_file" <<NETEOF
network:
  version: 2
NETEOF

        if [[ -n "$render_line" ]]; then
            echo "$render_line" >> "$netplan_file"
        fi

        cat >> "$netplan_file" <<NETEOF
  ethernets:
NETEOF
        
        # Si existe default_iface y no es la misma a la que le asignamos IP estática
        if [[ -n "$default_iface" && "$default_iface" != "$IFACE" ]]; then
            cat >> "$netplan_file" <<NETEOF
    $default_iface:
      dhcp4: true
NETEOF
        fi

        # Agregar nuestra interfaz estática
        cat >> "$netplan_file" <<NETEOF
    $IFACE:
      addresses:
        - $IP
      dhcp4: false
      nameservers:
        addresses: [127.0.0.1, 8.8.8.8]
NETEOF
        echo "Aplicando configuracion permanente de Netplan..."
        chmod 600 "$netplan_file"
        netplan apply || echo "Aviso: netplan apply fallo, revisa sintaxis yaml"
    fi
else
    echo "ADVERTENCIA: Netplan no detectado. El cambio de IP (comando 'ip addr') es TEMPORAL y se perdera al reiniciar."
    echo "Para hacerlo permanente en tu distro, configura NetworkManager (nmcli) o /etc/network/interfaces."
fi
echo "Proceso finalizado."

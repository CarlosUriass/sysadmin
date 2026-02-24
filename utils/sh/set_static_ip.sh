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

if [[ -z "$IFACE" || -z "$IP" ]]; then
    echo "Faltan parametros. Usa -h para ayuda."
    exit 1
fi

echo "Cambiando IP de $IFACE a $IP ..."

ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add "$IP" dev "$IFACE" 2>/dev/null
ip link set "$IFACE" up

NETPLAN_DIR="/etc/netplan"
if [[ -d "$NETPLAN_DIR" ]]; then
    netplan_file=$(find "$NETPLAN_DIR" -name "*.yaml" -type f | head -1)
    if [[ -n "$netplan_file" ]]; then
        cp "$netplan_file" "${netplan_file}.bak.$(date +%s)"
        
        # Necesitamos saber la default_iface para no romper netplan
        default_iface=$(ip route | awk '/default/ {print $5}' | head -1)
        
        cat > "$netplan_file" <<NETEOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $default_iface:
      dhcp4: true
    $IFACE:
      addresses:
        - $IP
      dhcp4: false
      nameservers:
        addresses: [127.0.0.1, 8.8.8.8]
NETEOF
        netplan apply 2>/dev/null || echo "Aviso: netplan apply fallo, IP asignada manualmente"
    fi
fi
echo "IP cambiada a $IP"

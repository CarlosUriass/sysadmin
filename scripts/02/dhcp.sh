#!/bin/bash
# Script para instalar, configurar y monitorear isc-dhcp-server
# Uso: sudo bash dchp-server.sh [--install|-i] [--configure|-c] [--leases|-l] [--status|-s] [--help|-h]

set -euo pipefail

IFACE=$(bash "$(dirname "$0")/../../utils/sh/get_internal_iface.sh")
CONF="/etc/dhcp/dhcpd.conf"
LEASES_FILE="/var/lib/dhcp/dhcpd.leases"
DEFAULT_CONF="/etc/default/isc-dhcp-server"
NETPLAN_DIR="/etc/netplan"

# Blacklist de IPs no validas
BLACKLIST=(
    "127."
    "255.255.255"
    "0.0.0.0"
    "224." "225." "226." "227." "228." "229."
    "230." "231." "232." "233." "234." "235." "236." "237." "238." "239."
)

# Validar formato IPv4 con helper script
validar_ip() {
    local ip="$1"
    bash "$(dirname "$0")/../../utils/sh/validate_ip.sh" --ip "$ip" >/dev/null 2>&1
    local status=$?
    if [[ $status -ne 0 ]]; then
        echo "Error: formato invalido o fuera de rango en '$ip'"
        return 1
    fi
    return 0
}

# Verificar si la IP esta en la blacklist
ip_en_blacklist() {
    local ip="$1"
    for entrada in "${BLACKLIST[@]}"; do
        if [[ "$ip" == "$entrada" ]] || [[ "$ip" == ${entrada}* ]]; then
            echo "Error: IP '$ip' esta en la blacklist (coincide con '$entrada')"
            return 0
        fi
    done
    return 1
}

# Solicitar y validar una IP
solicitar_ip() {
    local prompt="$1"
    local default="$2"
    local resultado=""

    while true; do
        read -rp "$prompt [$default]: " resultado
        resultado="${resultado:-$default}"

        if ! validar_ip "$resultado"; then
            echo "Intente de nuevo."
            continue
        fi
        if ip_en_blacklist "$resultado"; then
            echo "Intente con otra IP."
            continue
        fi
        echo "$resultado"
        return 0
    done
}

# Obtener subred /24 y prefijo de una IP
obtener_subred() { echo "${1%.*}.0"; }
obtener_prefijo() { echo "${1%.*}"; }

# IP actual de la interfaz
obtener_ip_actual() {
    ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1
}

# Adaptar IP estatica si el rango cambia de subred
adaptar_ip_estatica() {
    local rango_ip="$1"
    local nueva_subred=$(obtener_prefijo "$rango_ip")
    local ip_actual=$(obtener_ip_actual)
    [[ -z "$ip_actual" ]] && ip_actual="0.0.0.0"
    local subred_actual=$(obtener_prefijo "$ip_actual")

    if [[ "$subred_actual" == "$nueva_subred" ]]; then
        echo "La IP actual ($ip_actual) ya esta en la subred $nueva_subred.0/24"
        return 0
    fi

    local nueva_ip="${nueva_subred}.10"
    echo "La subred del rango ($nueva_subred.0/24) es diferente a la IP actual ($ip_actual)"
    echo "Cambiando IP de $IFACE a $nueva_ip/24 ..."

    ip addr flush dev "$IFACE" 2>/dev/null || true
    ip addr add "${nueva_ip}/24" dev "$IFACE" 2>/dev/null
    ip link set "$IFACE" up

    # Persistir en netplan si existe
    if [[ -d "$NETPLAN_DIR" ]]; then
        local netplan_file=$(find "$NETPLAN_DIR" -name "*.yaml" -type f | head -1)
        if [[ -n "$netplan_file" ]]; then
            cp "$netplan_file" "${netplan_file}.bak.$(date +%s)"
            cat > "$netplan_file" <<NETEOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $IFACE:
      addresses:
        - ${nueva_ip}/24
      dhcp4: false
NETEOF
            netplan apply 2>/dev/null || echo "Aviso: netplan apply fallo, IP asignada manualmente"
        fi
    fi
    echo "IP cambiada a $nueva_ip"
}

# Instalacion idempotente
instalar_dhcp() {
    echo "=== INSTALACION ==="
    if dpkg -s isc-dhcp-server &>/dev/null; then
        echo "isc-dhcp-server ya esta instalado"
    else
        echo "Instalando isc-dhcp-server..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq isc-dhcp-server
        echo "Instalacion completada"
    fi

    if [[ -f "$DEFAULT_CONF" ]]; then
        sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$IFACE\"/" "$DEFAULT_CONF"
        echo "Interfaz configurada: $IFACE"
    fi
}

# Configuracion interactiva
configurar_dhcp() {
    echo ""
    echo "=== CONFIGURACION DEL SCOPE DHCP ==="

    local scope_name=""
    read -rp "Nombre del Scope: " scope_name
    while [[ -z "$scope_name" ]]; do
        echo "El nombre no puede estar vacio."
        read -rp "Nombre del Scope: " scope_name
    done

    echo ""
    echo "Ingrese los parametros de red (Enter = valor por defecto):"
    echo ""

    local start_ip end_ip gateway dns lease

    start_ip=$(solicitar_ip "IP inicial del rango" "192.168.100.50")
    end_ip=$(solicitar_ip "IP final del rango" "192.168.100.150")
    gateway=$(solicitar_ip "Gateway" "192.168.100.1")
    dns=$(solicitar_ip "Servidor DNS" "192.168.100.10")

    echo ""
    read -rp "Lease time en segundos [600]: " lease
    lease="${lease:-600}"
    while ! [[ "$lease" =~ ^[0-9]+$ ]] || (( lease < 60 )); do
        echo "Ingrese un valor numerico >= 60"
        read -rp "Lease time en segundos [600]: " lease
        lease="${lease:-600}"
    done

    # Validar que start y end esten en la misma subred
    local start_prefix=$(obtener_prefijo "$start_ip")
    local end_prefix=$(obtener_prefijo "$end_ip")
    if [[ "$start_prefix" != "$end_prefix" ]]; then
        echo "Error: IP inicial y final deben estar en la misma subred"
        exit 1
    fi

    local start_last="${start_ip##*.}"
    local end_last="${end_ip##*.}"
    if (( start_last >= end_last )); then
        echo "Error: IP inicial ($start_ip) debe ser menor que IP final ($end_ip)"
        exit 1
    fi

    local subnet=$(obtener_subred "$start_ip")

    # Adaptar IP estatica si cambio la subred
    echo ""
    echo "=== VERIFICACION DE SUBRED ==="
    adaptar_ip_estatica "$start_ip"

    # Backup
    [[ -f "$CONF" ]] && cp "$CONF" "${CONF}.bak.$(date +%s)"

    # Generar dhcpd.conf
    echo ""
    echo "=== GENERANDO CONFIGURACION ==="
    cat > "$CONF" <<EOF
# Generado por dchp-server.sh - Scope: $scope_name
default-lease-time $lease;
max-lease-time $((lease * 2));
authoritative;

subnet $subnet netmask 255.255.255.0 {
    range $start_ip $end_ip;
    option routers $gateway;
    option domain-name-servers $dns;
    option subnet-mask 255.255.255.0;
}
EOF
    echo "Archivo $CONF generado"
    echo ""
    echo "Resumen:"
    echo "  Scope:    $scope_name"
    echo "  Subred:   $subnet/24"
    echo "  Rango:    $start_ip - $end_ip"
    echo "  Gateway:  $gateway"
    echo "  DNS:      $dns"
    echo "  Lease:    $lease seg"

    # Validar sintaxis
    echo ""
    echo "Validando configuracion..."
    if dhcpd -t -cf "$CONF" 2>/dev/null; then
        echo "Configuracion valida"
    else
        echo "Error de sintaxis en $CONF"
        exit 1
    fi

    # Reiniciar servicio
    systemctl restart isc-dhcp-server
    systemctl enable isc-dhcp-server 2>/dev/null
    echo "Servicio reiniciado y habilitado"
}

# Mostrar leases
mostrar_leases() {
    echo ""
    echo "=== LEASES ACTIVAS ==="
    if [[ ! -f "$LEASES_FILE" ]]; then
        echo "Archivo de leases no encontrado"
        return
    fi

    local count=$(grep -c "^lease " "$LEASES_FILE" 2>/dev/null || echo "0")
    if (( count == 0 )); then
        echo "No hay leases activas"
    else
        echo "$count lease(s) encontrada(s):"
        awk '
        /^lease / { ip=$2 }
        /hardware ethernet/ { mac=$3; gsub(/;/,"",mac) }
        /client-hostname/ { host=$2; gsub(/[";]/,"",host) }
        /^}/ {
            if (ip != "") {
                printf "  %-18s %-22s %s\n", ip, mac, host
                ip=""; mac=""; host=""
            }
        }' "$LEASES_FILE"
    fi
}

# Estado del servicio
mostrar_estado() {
    echo ""
    echo "=== ESTADO DEL SERVICIO ==="
    if systemctl is-active --quiet isc-dhcp-server; then
        echo "Servicio: ACTIVO"
    else
        echo "Servicio: INACTIVO"
    fi
    echo ""
    systemctl --no-pager status isc-dhcp-server 2>/dev/null || true
}

# Mostrar ayuda
mostrar_ayuda() {
    echo "Uso: sudo bash $0 [OPCION]"
    echo ""
    echo "Opciones:"
    echo "  -i, --install      Instalar isc-dhcp-server"
    echo "  -c, --configure    Configurar scope DHCP"
    echo "  -l, --leases       Ver leases activas"
    echo "  -s, --status       Estado del servicio"
    echo "  -h, --help         Mostrar ayuda"
    echo "  Sin opciones       Flujo completo (instalar + configurar)"
}

# Verificar root
verificar_root() {
    bash "$(dirname "$0")/../../utils/sh/permissions.sh" --check-root
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
}

# Main
main() {
    echo "=== DHCP Server - isc-dhcp-server ==="

    if [[ $# -eq 0 ]]; then
        verificar_root
        instalar_dhcp
        configurar_dhcp
        mostrar_estado
        mostrar_leases
        exit 0
    fi

    case "$1" in
        -i|--install)   verificar_root; instalar_dhcp ;;
        -c|--configure) verificar_root; instalar_dhcp; configurar_dhcp ;;
        -l|--leases)    verificar_root; mostrar_leases ;;
        -s|--status)    mostrar_estado ;;
        -h|--help)      mostrar_ayuda ;;
        *) echo "Opcion desconocida: $1"; mostrar_ayuda; exit 1 ;;
    esac
}

main "$@"

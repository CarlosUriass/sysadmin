#!/bin/bash
# ==============================================================================
# Script: setup_dns_linux.sh
# Dominio: reprobados.com
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Configuración Inicial y Strict Mode
# ------------------------------------------------------------------------------
set -euo pipefail

# Variables Globales
DOMAIN=""
IP_CLIENTE=""
IP_SERVIDOR=""
IFACE=""
GATEWAY=""
MASK=""
DNS1="8.8.8.8"
DNS2="1.1.1.1"

# Logs
LOG_FILE="/var/log/dns_setup.log"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Permisos
BIND_USER="bind"
BIND_GROUP="bind"

# Rutas
CONF_LOCAL="/etc/bind/named.conf.local"
CONF_OPTIONS="/etc/bind/named.conf.options"
ZONE_DIR="/var/cache/bind"
ZONE_FILE="${ZONE_DIR}/db.${DOMAIN}"

# ------------------------------------------------------------------------------
# 2. metodos base
# ------------------------------------------------------------------------------
log_info() { echo "info: $1"; echo "$(date) - info: $1" >> "$LOG_FILE"; }
log_ok() { echo "ok: $1"; echo "$(date) - ok: $1" >> "$LOG_FILE"; }
log_warn() { echo "alerta: $1"; echo "$(date) - alerta: $1" >> "$LOG_FILE"; }
log_error() { echo "error: $1" >&2; echo "$(date) - error: $1" >> "$LOG_FILE"; exit 1; }

trap 'log_error "fallo en linea $LINENO. abortando."' ERR

check_root() {
    bash "$(dirname "$0")/../../utils/sh/permissions.sh" --check-root >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        log_error "Privilegios insuficientes. Ejecute como root (sudo)."
    fi
}

validate_ipv4() {
    bash "$(dirname "$0")/../../utils/sh/validate_ip.sh" --ip "$1" >/dev/null 2>&1
    return $?
}

check_port_53() {
    if command -v ss &>/dev/null; then
        if ss -tulpn | grep -q ":53 "; then
            # Si es named está bien. systemd-resolved típicamente usa 127.0.0.53 y puede coexistir.
            if ! ss -tulpn | grep ":53 " | grep -qE "named|systemd-resolve"; then
                log_error "El puerto 53 TCP/UDP está reservado por otro proceso conflictivo."
            elif ss -tulpn | grep ":53 " | grep -q "systemd-resolve"; then
                log_warn "systemd-resolved detectado en el puerto 53 (usualmente 127.0.0.53). BIND9 coexistirá en otras interfaces."
            fi
        fi
    fi
}

# ------------------------------------------------------------------------------
# 3. Módulo de Red y Firewall
# ------------------------------------------------------------------------------
setup_firewall() {
    log_info "Verificando reglas de Firewall (UFW/IPTables)..."
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        ufw allow 53/tcp comment 'BIND9 DNS TCP' >/dev/null 2>&1 || true
        ufw allow 53/udp comment 'BIND9 DNS UDP' >/dev/null 2>&1 || true
        log_ok "Tráfico DNS habilitado en UFW."
    fi
}

setup_static_ip() {
    # Detectar la interfaz de red interna (la que NO tiene la ruta a internet default)
    local internal_iface=$(bash "$(dirname "$0")/../../utils/sh/get_internal_iface.sh")

    local current_ip=$(ip -4 addr show dev "$internal_iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    
    # Calcular automáticamente la IP del Servidor en base a la IP que el usuario pasó para el dominio
    local prefix=$(echo "$IP_CLIENTE" | cut -d. -f1-3)
    IP_SERVIDOR="${prefix}.10"
    
    # Evitar colisión si casualmente el usuario pidió que el dominio apunte a la .10
    if [[ "$IP_CLIENTE" == "$IP_SERVIDOR" ]]; then
        IP_SERVIDOR="${prefix}.11"
    fi
    
    log_info "IP de Dominio Objetivo: $IP_CLIENTE. Asignando IP de Servidor DNS automáticamente a: $IP_SERVIDOR"
    log_info "Interfaz de red interna detectada: $internal_iface (IP Local Actual: ${current_ip:-Ninguna})"
    
    if [[ "$current_ip" != "$IP_SERVIDOR" ]]; then
        log_info "La IP configurada ($current_ip) es distinta a la de servidor deseada ($IP_SERVIDOR). Aplicando cambio..."
        bash "$(dirname "$0")/../../utils/sh/set_static_ip.sh" --iface "$internal_iface" --ip "${IP_SERVIDOR}/24"
        log_ok "IP de Servidor $IP_SERVIDOR configurada en $internal_iface."
    else
        log_ok "La interfaz interna ya posee la IP de servidor solicitada ($current_ip)."
    fi
}

# ------------------------------------------------------------------------------
# 4. Instalación Segura BIND9
# ------------------------------------------------------------------------------
install_bind9() {
    log_info "Verificando dependencias de BIND9..."
    export DEBIAN_FRONTEND=noninteractive
    if dpkg -s bind9 &>/dev/null; then
        log_ok "BIND9 ya está instalado. Omitiendo apt-get."
    else
        bash "$(dirname "$0")/../../utils/sh/install_package.sh" -p bind9 bind9utils bind9-doc dnsutils
        log_ok "Paquetes instalados."
    fi
}

# ------------------------------------------------------------------------------
# 5. Hardening (Opciones) e Idempotencia en Configuración
# ------------------------------------------------------------------------------
configure_hardening() {
    log_info "Aplicando Hardening a BIND9 (named.conf.options)..."
    cp "$CONF_OPTIONS" "${CONF_OPTIONS}.bak.$(date +%F)" 2>/dev/null || true
    
    cat <<EOF > "$CONF_OPTIONS"
acl "trusted" {
    127.0.0.0/8;
    any;
};

options {
    directory "/var/cache/bind";
    recursion yes;            // Permitir que la maquina navegue a internet
    allow-recursion { trusted; };
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };
    allow-transfer { none; }; // Evitar AXFR leaks
    allow-update { none; };   // Sin updates dinámicos
    allow-query { any; };
    listen-on { any; };
    dnssec-validation auto;
    auth-nxdomain no;    
};
EOF
    log_ok "configuracion de options aplicada."
}

inject_named_local() {
    log_info "Configurando Referencia de Zona maestra..."
    cp "$CONF_LOCAL" "${CONF_LOCAL}.bak.$(date +%F)" 2>/dev/null || true
    
    # Evitar inyección duplicada si ya se halla el bloque exacto
    if ! grep -q "zone \"$DOMAIN\" {" "$CONF_LOCAL"; then
        cat <<EOF >> "$CONF_LOCAL"

zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF
        log_ok "Bloque de zona $DOMAIN inyectado correctamente."
    else
        log_ok "La referencia de zona ya existe en $CONF_LOCAL. Omitiendo duplicidad."
    fi
}

# ------------------------------------------------------------------------------
# 6. Serial Automático y Contrucción de Registros
# ------------------------------------------------------------------------------
generate_zone_file() {
    log_info "Sintetizando estructura y Serial de zona para $DOMAIN..."
    local NEW_SERIAL=""
    local CURRENT_DATE=$(date +"%Y%m%d")
    
    if [[ -f "$ZONE_FILE" ]]; then
        # Extraer serial actual
        local CURRENT_SERIAL=$(grep -i "serial" "$ZONE_FILE" | awk '{print $1}')
        if [[ -n "$CURRENT_SERIAL" && "$CURRENT_SERIAL" =~ ^[0-9]{10}$ ]]; then
            local SERIAL_DATE=${CURRENT_SERIAL:0:8}
            local SERIAL_NUM=${CURRENT_SERIAL:8:2}
            
            if [[ "$SERIAL_DATE" == "$CURRENT_DATE" ]]; then
                NEW_SERIAL="${SERIAL_DATE}$(printf "%02d" $((10#$SERIAL_NUM + 1)))"
            else
                NEW_SERIAL="${CURRENT_DATE}01"
            fi
        else
            NEW_SERIAL="${CURRENT_DATE}01"
        fi
        cp "$ZONE_FILE" "${ZONE_FILE}.bak.$(date +%F-%H%M)"
    else
        NEW_SERIAL="${CURRENT_DATE}01"
    fi

    # Sobreescritura total controlada
    cat <<EOF > "$ZONE_FILE"
\$TTL    86400
@       IN      SOA     ns1.$DOMAIN. admin.$DOMAIN. (
                     $NEW_SERIAL    ; Serial
                         604800     ; Refresh
                          86400     ; Retry
                        2419200     ; Expire
                          86400 )   ; Negative Cache TTL

; --- Name Servers ---
@       IN      NS      ns1.$DOMAIN.
ns1     IN      A       $IP_SERVIDOR

; --- Registros Peticion ---
@       IN      A       $IP_CLIENTE
www     IN      CNAME   $DOMAIN.
EOF
    
    # Asignar dueño correcto
    chown $BIND_USER:$BIND_GROUP "$ZONE_FILE"
    chmod 644 "$ZONE_FILE"
    log_ok "Archivo de zona escrito con serial $NEW_SERIAL."
}

# ------------------------------------------------------------------------------
# 7. Validaciones Pre-Reinicio y Checklist de Operación
# ------------------------------------------------------------------------------
validate_and_restart() {
    log_info "Verificando sintaxis crítica antes de aplicar..."
    if ! named-checkconf >/dev/null; then
        log_error "Fallo fatal en named-checkconf. Revisa configuraciones."
    fi
    
    if ! named-checkzone "$DOMAIN" "$ZONE_FILE" >/dev/null; then
        log_error "Fallo fatal en named-checkzone ($ZONE_FILE). Revisa registros."
    fi
    log_ok "Sintaxis binaria aprobada."
    
    systemctl stop bind9 2>/dev/null || true
    # Forzar la limpieza de cache y temporales jnl si los hubiera
    rm -f ${ZONE_FILE}.jnl
    
    systemctl start bind9 || log_error "Fallo al iniciar Demonio bind9."
    systemctl enable bind9 2>/dev/null || true
    log_ok "Daemon BIND9 reiniciado y activo sin cache."

    log_info "Forzando a la máquina local a usar BIND9 como su DNS principal..."
    # Si systemd-resolved existe, le indicamos que use el servidor DNS local (127.0.0.1)
    if command -v resolvectl &>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat <<EOF > /etc/systemd/resolved.conf.d/dns_servers.conf
[Resolve]
DNS=127.0.0.1
Domains=~.
EOF
        systemctl restart systemd-resolved
        log_ok "systemd-resolved reconfigurado para usar 127.0.0.1."
    elif [ -f "/etc/resolv.conf" ]; then
        # Backwards compatibility
        sed -i '1i nameserver 127.0.0.1' /etc/resolv.conf
        log_ok "/etc/resolv.conf modificado para priorizar 127.0.0.1."
    fi
}

self_diagnostic() {
    echo ""
    echo "--- checklist ---"
    
    if systemctl is-active --quiet bind9; then echo "bind9: ok"; else echo "bind9: fail"; fi
    if ss -lntu | grep -q ":53 "; then echo "puerto 53: ok"; else echo "puerto 53: fail"; fi
    
    if nslookup -timeout=2 "$DOMAIN" 127.0.0.1 | grep -q 'Address:'; then
       echo "nslookup $DOMAIN: ok"
    else 
       echo "nslookup $DOMAIN: fail"
    fi
    
    if nslookup -timeout=2 "www.$DOMAIN" 127.0.0.1 | grep -q 'name ='; then
       echo "nslookup www.$DOMAIN: ok"
    else 
       echo "nslookup www.$DOMAIN: fail"
    fi
}

# ------------------------------------------------------------------------------
# 8. Integración dinámica con DHCP
# ------------------------------------------------------------------------------
integrate_dhcp() {
    log_info "Verificando integración con DHCP en la red interna..."
    local dhcp_conf="/etc/dhcp/dhcpd.conf"
    
    # Obtener IP de la red interna
    local internal_iface=$(bash "$(dirname "$0")/../../utils/sh/get_internal_iface.sh")

    local ACTIVE_IP=$(ip -4 addr show dev "$internal_iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    
    if [[ -z "$ACTIVE_IP" ]]; then
        log_warn "No se detectó IP en la interfaz interna ($internal_iface). Omitiendo integración DHCP."
        return
    fi

    if ! dpkg -s isc-dhcp-server &>/dev/null; then
        log_info "Servicio DHCP no encontrado. Instalando isc-dhcp-server..."
        bash "$(dirname "$0")/../../utils/sh/install_package.sh" -p isc-dhcp-server >/dev/null 2>&1 || true
    fi

    local prefix=$(echo "$ACTIVE_IP" | cut -d. -f1-3)
    local subnet="${prefix}.0"
    local gw="${prefix}.1"
    local start_ip="${prefix}.50"
    local end_ip="${prefix}.150"
    
    log_info "Generando configuración DHCP para la subred $subnet/24..."
    cat > "$dhcp_conf" <<EOF
# Generado dinamicamente por DNS Script
default-lease-time 600;
max-lease-time 7200;
authoritative;

subnet $subnet netmask 255.255.255.0 {
    range $start_ip $end_ip;
    option routers $gw;
    option domain-name-servers $ACTIVE_IP;
}
EOF
    
    local DEFAULT_CONF="/etc/default/isc-dhcp-server"
    if [[ -n "$internal_iface" && -f "$DEFAULT_CONF" ]]; then
        sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$internal_iface\"/" "$DEFAULT_CONF"
    fi

    systemctl restart isc-dhcp-server || log_warn "Problemas al iniciar DHCP. Revisa journalctl -u isc-dhcp-server."
    systemctl enable isc-dhcp-server 2>/dev/null || true
    log_ok "DHCP enrutando correctamente sobre la interfaz $internal_iface (Subred: $subnet)."
}

# ------------------------------------------------------------------------------
# M A I N  E X E C U T I O N 
# ------------------------------------------------------------------------------
echo "Iniciando Setup BIND9 Enterprise..."
touch "$LOG_FILE" && chmod 644 "$LOG_FILE"
log_info "---- NUEVA EJECUCIÓN DEL SCRIPT BIND9 ----"

check_root
check_port_53
setup_firewall

# Recolección Argumentos UI/Interactivo 
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help)
            echo "uso:"
            echo "  sudo ./setup_dns_linux.sh [opciones]"
            echo ""
            echo "opciones:"
            echo "  -d, --domain <dominio> asigna el nombre de dominio a configurar."
            echo "  -ip <direccion>       asigna la ip a donde resolverá el dominio (Web Server). El script automatizará su propia red en base a esto."
            echo "  --purge               elimina bind9, sus configuraciones y sale."
            echo "  -h, --help            muestra este mensaje de ayuda."
            exit 0
            ;;
        --purge)
            log_warn "iniciando purga total de bind9..."
            systemctl stop bind9 2>/dev/null || true
            apt-get purge -y bind9 bind9utils bind9-doc dnsutils >/dev/null 2>&1
            rm -rf /etc/bind /var/cache/bind
            log_ok "bind9 desinstalado y carpetas eliminadas."
            exit 0
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift
            ;;
        -ip) 
            IP_CLIENTE="$2"
            shift 
            ;;
        *) 
            log_warn "parametro desconocido: $1. use -h para ayuda." 
            exit 1
            ;;
    esac
    shift
done

while [[ -z "$DOMAIN" ]]; do
    read -p "Ingrese el nombre de Dominio (ej. local.test): " DOMAIN
done

while ! validate_ipv4 "$IP_CLIENTE"; do
    read -p "Ingrese una IP Válida de cliente objetivo (A Record): " IP_CLIENTE
done

setup_static_ip
install_bind9
configure_hardening
inject_named_local
generate_zone_file
validate_and_restart
integrate_dhcp

# Purge cache
rndc flush 2>/dev/null || true

self_diagnostic
log_ok "Ciclo completo sin errores."
exit 0

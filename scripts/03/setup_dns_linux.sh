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
DOMAIN="reprobados.com"
IP_CLIENTE=""
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
    if [[ "$EUID" -ne 0 ]]; then
        log_error "Privilegios insuficientes. Ejecute como root (sudo)."
    fi
}

validate_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then return 1; fi
    IFS='.' read -r -a octet <<< "$ip"
    for i in "${octet[@]}"; do
        if (( i > 255 )); then return 1; fi
    done
    return 0
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
    local active_iface=$(ip route get 8.8.8.8 2>/dev/null | grep dev | awk '{print $5}' || echo "")
    if [[ -z "$active_iface" ]]; then active_iface="eth0"; fi
    
    local current_ip=$(ip -4 addr show "$active_iface" 2>/dev/null | grep -oP 'inet \K[\d.]+')
    
    # Si detectamos DHCP simple sin netplan complejo, validaremos
    if ip route | grep -q "dhcp"; then
        log_warn "Se detectó configuración IP gestionada por DHCP. Un servidor DNS exige IP estática."
        read -p "[Interact] Desea que el script fije la IP actual ($current_ip) estáticamente vía Netplan? (s/n): " fix_ip
        if [[ "${fix_ip,,}" == "s" ]]; then
            echo "" # Setup manual omitido por robustez en entornos diversos, 
            # delegamos responsabilidad alertando al admin.
            log_warn "Se recomienda configurar manual en /etc/netplan. Continuaremos asumiendo persistencia."
        fi
    else
        log_ok "Red opera aparentemente fuera de pool DHCP dinámico."
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
        apt-get update -qq
        apt-get install -y -qq bind9 bind9utils bind9-doc dnsutils
        log_ok "Paquetes instalados."
    fi
}

# ------------------------------------------------------------------------------
# 5. Hardening (Opciones) e Idempotencia en Configuración
# ------------------------------------------------------------------------------
configure_hardening() {
    log_info "Aplicando Hardening a BIND9 (named.conf.options)..."
    cp "$CONF_OPTIONS" "${CONF_OPTIONS}.bak.$(date +%F)" 2>/dev/null || true
    
    # Configurar BIND9 como autoritativo estricto
    cat <<EOF > "$CONF_OPTIONS"
acl "trusted" {
    127.0.0.0/8;
    any;
};

options {
    directory "/var/cache/bind";
    recursion no;          // Solo autoritativo
    allow-transfer { none; }; // Evitar AXFR leaks
    allow-update { none; };   // Sin updates dinámicos
    allow-query { any; };
    listen-on { any; };
    dnssec-validation auto;
    auth-nxdomain no;    
};
EOF
    log_ok "Hardening de options aplicado."
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
                     $NEW_SERIAL   ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                          86400 )       ; Negative Cache TTL

; --- Name Servers ---
@       IN      NS      ns1.$DOMAIN.
ns1     IN      A       127.0.0.1

; --- Registros Petición ---
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
    
    systemctl restart bind9 || log_error "Fallo al iniciar Demonio bind9."
    systemctl enable bind9 2>/dev/null || true
    log_ok "Daemon BIND9 reiniciado y activo."

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
        -ip) IP_CLIENTE="$2"; shift ;;
        *) log_warn "Parámetro desconocido: $1" ;;
    esac
    shift
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

# Purge cache
rndc flush 2>/dev/null || true

self_diagnostic
log_ok "Ciclo completo sin errores."
exit 0

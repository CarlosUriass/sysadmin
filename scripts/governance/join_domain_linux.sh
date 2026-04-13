#!/bin/bash
# ==============================================================================
# Script: join_domain_linux.sh
# Descripcion: Une un cliente Linux al dominio de Active Directory.
#              Instala realmd, sssd, adcli. Configura fallback_homedir
#              y permisos de sudo para usuarios de AD.
# Uso: sudo bash join_domain_linux.sh [--domain <dominio>]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# LOGGING & UTILIDADES
# ==============================================================================
source "$SCRIPT_DIR/../../utils/logs/logger.sh"

verificar_root() {
    "$SCRIPT_DIR/../../utils/sh/permissions.sh" --check-root
    if [[ $? -ne 0 ]]; then
        log_error "Ejecutar como root (sudo)."
    fi
}

esperar_apt() {
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        log_warn "Apt bloqueado. Esperando 5s..."
        sleep 5
    done
}

# ==============================================================================
# PARSEO DE ARGUMENTOS
# ==============================================================================
DOMAIN=""
ADMIN_USER="Administrator"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --domain|-d)
            DOMAIN="$2"
            shift
            ;;
        --user|-u)
            ADMIN_USER="$2"
            shift
            ;;
        -h|--help)
            echo "uso: sudo bash $0 [--domain <dominio>] [--user <admin>]"
            echo "  --domain   nombre del dominio AD (ej. laboratorio.local)"
            echo "  --user     usuario admin del dominio (default: Administrator)"
            echo "  --help     muestra este mensaje"
            exit 0
            ;;
        *)
            echo "parametro desconocido: $1. Use --help"
            exit 1
            ;;
    esac
    shift
done

# ==============================================================================
# MAIN
# ==============================================================================
echo "=== Union al Dominio — Cliente Linux ==="

verificar_root

# Solicitar dominio si no se proporciono
if [[ -z "$DOMAIN" ]]; then
    read -rp "nombre del dominio (ej. laboratorio.local): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        log_error "nombre de dominio vacio."
    fi
fi

DOMAIN_UPPER=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

# ==============================================================================
# 1. INSTALAR PAQUETES NECESARIOS
# ==============================================================================
log_info "instalando paquetes necesarios..."
esperar_apt
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y realmd sssd sssd-tools adcli krb5-user packagekit samba-common-bin -qq

log_success "paquetes instalados"

# ==============================================================================
# 2. DESCUBRIR EL DOMINIO
# ==============================================================================
log_info "descubriendo dominio $DOMAIN ..."
realm discover "$DOMAIN"

if [[ $? -ne 0 ]]; then
    log_error "no se pudo descubrir el dominio $DOMAIN. Verifique la red y DNS."
fi

log_success "dominio descubierto"

# ==============================================================================
# 3. UNIRSE AL DOMINIO
# ==============================================================================
# Verificar si ya esta unido
if realm list | grep -qi "$DOMAIN"; then
    log_info "este equipo ya esta unido al dominio $DOMAIN"
else
    log_info "uniendo equipo al dominio $DOMAIN con usuario $ADMIN_USER ..."
    realm join --user="$ADMIN_USER" "$DOMAIN"
    log_success "equipo unido al dominio $DOMAIN"
fi

# ==============================================================================
# 4. CONFIGURAR SSSD (fallback_homedir)
# ==============================================================================
log_info "configurando /etc/sssd/sssd.conf ..."

SSSD_CONF="/etc/sssd/sssd.conf"

if [[ -f "$SSSD_CONF" ]]; then
    # Backup
    cp "$SSSD_CONF" "${SSSD_CONF}.bak"

    # Configurar fallback_homedir
    if grep -q "^fallback_homedir" "$SSSD_CONF"; then
        sed -i 's|^fallback_homedir.*|fallback_homedir = /home/%u@%d|' "$SSSD_CONF"
    else
        # Agregar bajo la seccion [domain/...]
        sed -i "/^\[domain\//a fallback_homedir = /home/%u@%d" "$SSSD_CONF"
    fi

    # Asegurar que se creen los directorios home automaticamente
    if ! grep -q "^override_homedir" "$SSSD_CONF"; then
        :  # no override, usamos fallback
    fi

    log_success "sssd.conf configurado con fallback_homedir = /home/%u@%d"
else
    log_warn "sssd.conf no encontrado. SSSD puede no haberse configurado correctamente."
fi

# Habilitar creacion automatica de home
if ! grep -q "pam_mkhomedir" /etc/pam.d/common-session 2>/dev/null; then
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" >> /etc/pam.d/common-session
    log_success "pam_mkhomedir habilitado"
fi

# ==============================================================================
# 5. CONFIGURAR SUDOERS PARA USUARIOS DE AD
# ==============================================================================
log_info "configurando permisos de sudo para usuarios de AD ..."

SUDOERS_FILE="/etc/sudoers.d/ad-admins"

cat > "$SUDOERS_FILE" <<EOF
# Permitir a los administradores de dominio ejecutar sudo
%domain\ admins@${DOMAIN} ALL=(ALL) ALL

# Permitir al grupo GrupoCuates ejecutar sudo
%GrupoCuates@${DOMAIN} ALL=(ALL) ALL
EOF

chmod 440 "$SUDOERS_FILE"
chown root:root "$SUDOERS_FILE"

# Validar sintaxis
if visudo -c -f "$SUDOERS_FILE" >/dev/null 2>&1; then
    log_success "sudoers configurado: $SUDOERS_FILE"
else
    log_error "error de sintaxis en $SUDOERS_FILE"
fi

# ==============================================================================
# 6. REINICIAR SSSD
# ==============================================================================
log_info "reiniciando sssd ..."
systemctl restart sssd
systemctl enable sssd

log_success "sssd reiniciado y habilitado"

# ==============================================================================
# RESUMEN
# ==============================================================================
echo ""
echo "--- resumen ---"
echo "  dominio:        $DOMAIN"
echo "  fallback_home:  /home/%u@%d"
echo "  sudoers:        $SUDOERS_FILE"
echo "  estado sssd:    $(systemctl is-active sssd)"
echo ""

log_success "union al dominio completada"

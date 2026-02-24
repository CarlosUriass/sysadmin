#!/bin/bash
# ==============================================================================
# Script: ssh.sh
# Descripcion: Instala, configura y gestiona el servicio SSH en Linux
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Utils ---
check_root() {
    bash "$SCRIPT_DIR/../../utils/sh/permissions.sh" --check-root
    if [[ $? -ne 0 ]]; then exit 1; fi
}

# --- Instalar ---
instalar_ssh() {
    echo "=== INSTALACION SSH ==="
    bash "$SCRIPT_DIR/../../utils/sh/install_package.sh" -p openssh-server
}

# --- Habilitar y arrancar ---
habilitar_ssh() {
    echo "=== HABILITANDO SSH ==="
    systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
    systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true
    echo "ok: servicio SSH habilitado en el boot y arrancado"
}

# --- Firewall ---
configurar_firewall() {
    echo "=== FIREWALL ==="
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1 || true
        echo "ok: puerto 22 habilitado en UFW"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        echo "ok: SSH habilitado en firewalld"
    else
        echo "info: no se detecto firewall activo (ufw/firewalld)"
    fi
}

# --- Estado ---
mostrar_estado() {
    echo ""
    echo "=== ESTADO SSH ==="
    if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
        echo "servicio: ACTIVO"
    else
        echo "servicio: INACTIVO"
    fi

    if systemctl is-enabled --quiet ssh 2>/dev/null || systemctl is-enabled --quiet sshd 2>/dev/null; then
        echo "boot: HABILITADO"
    else
        echo "boot: DESHABILITADO"
    fi

    echo ""
    systemctl --no-pager status ssh 2>/dev/null || systemctl --no-pager status sshd 2>/dev/null || true
}

# --- Desactivar ---
desactivar_ssh() {
    echo "=== DESACTIVANDO SSH ==="
    systemctl stop ssh 2>/dev/null || systemctl stop sshd 2>/dev/null || true
    systemctl disable ssh 2>/dev/null || systemctl disable sshd 2>/dev/null || true
    echo "ok: servicio SSH detenido y deshabilitado del boot"
}

# --- Ayuda ---
mostrar_ayuda() {
    echo "Uso: sudo bash $0 [OPCION]"
    echo ""
    echo "Opciones:"
    echo "  -i, --install      Instalar openssh-server"
    echo "  -e, --enable       Habilitar y arrancar SSH"
    echo "  -d, --disable      Detener y deshabilitar SSH"
    echo "  -s, --status       Mostrar estado del servicio"
    echo "  -h, --help         Mostrar ayuda"
    echo "  Sin opciones       Flujo completo (instalar + habilitar + firewall)"
}

# --- Main ---
main() {
    echo "=== SSH Server - Linux ==="

    if [[ $# -eq 0 ]]; then
        check_root
        instalar_ssh
        habilitar_ssh
        configurar_firewall
        mostrar_estado
        exit 0
    fi

    case "$1" in
        -i|--install)   check_root; instalar_ssh ;;
        -e|--enable)    check_root; habilitar_ssh; configurar_firewall ;;
        -d|--disable)   check_root; desactivar_ssh ;;
        -s|--status)    mostrar_estado ;;
        -h|--help)      mostrar_ayuda ;;
        *) echo "Opcion desconocida: $1"; mostrar_ayuda; exit 1 ;;
    esac
}

main "$@"

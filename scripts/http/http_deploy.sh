#!/bin/bash
# ==============================================================================
# Script: http_deploy.sh
# description: Despliegue dinámico de servicios HTTP en Linux (Apache/Nginx)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UTILS_DIR="$SCRIPT_DIR/../../utils/sh"

# Importar logger si existe
if [[ -f "$SCRIPT_DIR/../../utils/logs/logger.sh" ]]; then
    source "$SCRIPT_DIR/../../utils/logs/logger.sh"
else
    log_info() { echo "[INFO] $1"; }
    log_success() { echo "[OK] $1"; }
    log_warn() { echo "[WARN] $1"; }
    log_error() { echo "[FAIL] $1" >&2; exit 1; }
fi

# Variables
SERVICE=""
PORT=0
VERSION=""
LIST_VERSIONS=false
STATUS=false
PURGE=false

# --- Ayuda ---
show_help() {
    echo "Uso: $0 [OPCIONES]"
    echo ""
    echo "Opciones:"
    echo "  --service <srv>       Servicio a instalar (apache, nginx)"
    echo "  --port <num>          Puerto de escucha"
    echo "  --version <ver>       Versión específica a instalar"
    echo "  --list-versions       Listar versiones disponibles para el servicio"
    echo "  --status              Mostrar estado de los servicios"
    echo "  --purge               Eliminar servicios y archivos"
    echo "  -h, --help            Mostrar esta ayuda"
}

# --- Parsear argumentos ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --service) SERVICE="$2"; shift ;;
        --port) PORT="$2"; shift ;;
        --version) VERSION="$2"; shift ;;
        --list-versions) LIST_VERSIONS=true ;;
        --status) STATUS=true ;;
        --purge) PURGE=true ;;
        -h|--help) show_help; exit 0 ;;
        *) echo "Opción desconocida: $1"; show_help; exit 1 ;;
    esac
    shift
done

# --- Validaciones ---
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (sudo)."
    fi
}

# --- Listar Versiones ---
list_available_versions() {
    local srv=$1
    log_info "Consultando versiones disponibles para $srv..."
    case $srv in
        apache|apache2)
            apt-get update -qq
            apt-cache madison apache2 | awk '{print $3}' | head -n 5
            ;;
        nginx)
            apt-get update -qq
            apt-cache madison nginx | awk '{print $3}' | head -n 5
            ;;
        *)
            log_error "Servicio no soportado para listado: $srv"
            ;;
    esac
}

# --- Verificar Puerto ---
check_port() {
    local p=$1
    if lsof -Pi :"$p" -sTCP:LISTEN -t >/dev/null 2>&1; then
        local suggestions=()
        for ((i=p+1; i<=p+20 && i<=65535; i++)); do
            if ! lsof -Pi :"$i" -sTCP:LISTEN -t >/dev/null 2>&1; then
                suggestions+=("$i")
            fi
            [[ ${#suggestions[@]} -ge 3 ]] && break
        done
        
        local msg="El puerto $p ya está en uso."
        if [[ ${#suggestions[@]} -gt 0 ]]; then
            msg="$msg Puertos cercanos disponibles: ${suggestions[*]}"
        fi
        log_error "$msg"
    fi
}

# --- Instalación ---
install_web_server() {
    local srv=$1
    local p=$2
    local ver=$3

    check_port "$p"

    log_info "Instalando $srv ($ver) en puerto $p..."
    
    local pkg_name=$srv
    if [[ "$srv" == "apache" ]]; then pkg_name="apache2"; fi

    if [[ -n "$ver" ]]; then
        apt-get update -qq
        apt-get install -y "$pkg_name=$ver" || log_error "No se pudo instalar la versión $ver de $pkg_name."
    else
        bash "$UTILS_DIR/install_package.sh" -p "$pkg_name"
    fi

    # Configuración de puerto
    if [[ "$srv" == "apache" ]]; then
        sed -i "s/Listen 80/Listen $p/" /etc/apache2/ports.conf
        sed -i "s/<VirtualHost \*:80>/<VirtualHost *:$p>/" /etc/apache2/sites-available/000-default.conf
        systemctl restart apache2
    elif [[ "$srv" == "nginx" ]]; then
        sed -i "s/listen 80 default_server;/listen $p default_server;/" /etc/nginx/sites-available/default
        sed -i "s/listen \[::\]:80 default_server;/listen [::]:$p default_server;/" /etc/nginx/sites-available/default
        systemctl restart nginx
    fi

    log_success "$srv instalado y configurado en puerto $p."
}

# --- Main Logic ---
if $STATUS; then
    echo "=== Estado de Servicios ==="
    systemctl status apache2 nginx --no-pager 2>/dev/null || true
    exit 0
fi

if $PURGE; then
    check_root
    log_warn "Purgando servicios..."
    apt-get purge -y apache2 nginx >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    log_success "Sistema limpio."
    exit 0
fi

if [[ -n "$SERVICE" ]]; then
    check_root
    if $LIST_VERSIONS; then
        list_available_versions "$SERVICE"
        exit 0
    fi

    if [[ "$PORT" -eq 0 ]]; then
        log_error "El parámetro --port es obligatorio."
    fi

    install_web_server "$SERVICE" "$PORT" "$VERSION"
    exit 0
fi

# Modo interactivo básico si no hay parámetros
if [[ -z "$SERVICE" && "$STATUS" == false && "$PURGE" == false ]]; then
    show_help
    exit 1
fi

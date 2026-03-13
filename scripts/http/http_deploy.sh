#!/bin/bash
# ==============================================================================
# Script: http_deploy.sh
# description: Despliegue dinámico y hardening HTTP (Práctica 6)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UTILS_DIR="$SCRIPT_DIR/../../utils/sh"

# ==============================================================================
# LOGGING
# ==============================================================================
log_info()    { echo -e "\e[34m[INFO]\e[0m $(date +%H:%M:%S) - $1"; }
log_success() { echo -e "\e[32m[OK]\e[0m   $(date +%H:%M:%S) - $1"; }
log_warn()    { echo -e "\e[33m[WARN]\e[0m $(date +%H:%M:%S) - $1"; }
log_error()   { echo -e "\e[31m[FAIL]\e[0m $(date +%H:%M:%S) - $1" >&2; exit 1; }

# ==============================================================================
# SECURITY & UTILS
# ==============================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then log_error "Requiere privilegios de root (sudo)"; fi
}

check_port() {
    local p=$1
    if lsof -Pi :"$p" -sTCP:LISTEN -t >/dev/null 2>&1; then
        local suggestions=()
        for ((i=p+1; i<=p+20; i++)); do
            if ! lsof -Pi :"$i" -sTCP:LISTEN -t >/dev/null 2>&1; then
                suggestions+=("$i")
                [[ ${#suggestions[@]} -ge 3 ]] && break
            fi
        done
        log_error "Puerto $p ocupado. Recomendaciones: ${suggestions[*]}"
    fi
}

wait_for_apt_lock() {
    log_info "Verificando bloqueos de apt/dpkg..."
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        log_warn "El sistema está realizando actualizaciones en segundo plano. Esperando 5 segundos..."
        sleep 5
    done
}

configure_firewall() {
    local port=$1
    log_info "Configurando Firewall (UFW)..."
    if command -v ufw >/dev/null; then
        ufw allow "$port"/tcp comment "HTTP Practice 6" >/dev/null
        # Cerrar puertos por defecto si no se usan (simulacion interactiva suele ser peligrosa, solo informamos)
        log_info "Puerto $port habilitado en UFW."
    fi
}

create_service_user() {
    local user=$1
    local dir=$2
    if ! id "$user" &>/dev/null; then
        useradd -r -s /usr/sbin/nologin "$user"
    fi
    chown -R "$user":"$user" "$dir"
    chmod -R 755 "$dir"
    log_info "Usuario dedicado '$user' configurado para el directorio $dir"
}

# ==============================================================================
# INSTALLATION LOGIC
# ==============================================================================

generate_index() {
    local path=$1
    local srv=$2
    local ver=$3
    local port=$4
    echo "<h1>Servidor: $srv - Versión: $ver - Puerto: $port</h1><p>Aprovisionamiento Automatizado - Linux (Práctica 6)</p><p>Fecha: $(date)</p>" > "$path"
}

install_apache() {
    local p=$1
    local ver=$2
    check_port "$p"
    log_info "Instalando Apache..."
    [[ -n "$ver" ]] && pkg="apache2=$ver" || pkg="apache2"
    apt-get update -qq && apt-get install -y -qq apache2
    
    # Hardening
    sed -i "s/Listen 80/Listen $p/" /etc/apache2/ports.conf
    sed -i "s/ServerTokens .*/ServerTokens Prod/" /etc/apache2/conf-available/security.conf
    sed -i "s/ServerSignature .*/ServerSignature Off/" /etc/apache2/conf-available/security.conf
    
    # Encabezados de Seguridad
    a2enmod headers >/dev/null
    echo "Header set X-Frame-Options: SAMEORIGIN" >> /etc/apache2/apache2.conf
    echo "Header set X-Content-Type-Options: nosniff" >> /etc/apache2/apache2.conf
    
    # Restringir metodos
    echo "<Directory /var/www/html/>
    <LimitExcept GET POST>
        Deny from all
    </LimitExcept>
</Directory>" >> /etc/apache2/apache2.conf

    generate_index "/var/www/html/index.html" "Apache" "$ver" "$p"
    create_service_user "www-data" "/var/www/html"
    systemctl restart apache2
}

install_nginx() {
    local p=$1
    local ver=$2
    check_port "$p"
    log_info "Instalando Nginx..."
    apt-get update -qq && apt-get install -y -qq nginx
    
    local conf="/etc/nginx/sites-available/default"
    sed -i "s/listen 80 default_server;/listen $p default_server;/" "$conf"
    sed -i "s/listen \[::\]:80 default_server;/listen [::]:$p default_server;/" "$conf"
    
    # Hardening y Headers en nginx.conf
    sed -i "s/# server_tokens off;/server_tokens off;/" /etc/nginx/nginx.conf
    sed -i "/http {/a \    add_header X-Frame-Options SAMEORIGIN;\n    add_header X-Content-Type-Options nosniff;" /etc/nginx/nginx.conf

    generate_index "/var/www/html/index.html" "Nginx" "$ver" "$p"
    create_service_user "www-data" "/var/www/html"
    systemctl restart nginx
}

install_tomcat() {
    local p=$1
    local ver=$2 # Ej: 9.0.98
    check_port "$p"
    log_info "Instalando Tomcat $ver (Binario)..."
    
    # Requerimientos para tomcat (Java)
    apt-get update -qq && apt-get install -y -qq default-jdk wget tar
    
    local major=$(echo "$ver" | cut -d. -f1)
    local url="https://archive.apache.org/dist/tomcat/tomcat-$major/v$ver/bin/apache-tomcat-$ver.tar.gz"
    local dest="/opt/tomcat$major"
    
    if [[ ! -d "$dest" ]]; then
        mkdir -p "$dest"
        wget -qO /tmp/tomcat.tar.gz "$url"
        tar -xzf /tmp/tomcat.tar.gz -C "$dest" --strip-components=1
    fi
    
    # Cambiar puerto
    sed -i "s/port=\"8080\"/port=\"$p\"/" "$dest/conf/server.xml"
    
    # Hardening básico tomcat (remover version de logs y errores suele requerir valve config, lo omitimos por simplicidad en shell)
    
    generate_index "$dest/webapps/ROOT/index.html" "Tomcat" "$ver" "$p"
    create_service_user "tomcat" "$dest"
    
    # Preparar servicio SystemD
    echo "[Unit]
Description=Apache Tomcat $major
After=network.target

[Service]
Type=forking
User=tomcat
Group=tomcat
Environment=CATALINA_PID=$dest/temp/tomcat.pid
Environment=CATALINA_HOME=$dest
ExecStart=$dest/bin/startup.sh
ExecStop=$dest/bin/shutdown.sh

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/tomcat$major.service

    systemctl daemon-reload
    systemctl enable tomcat$major --now
}

purge_services() {
    check_root
    log_warn "Iniciando purga total de servicios HTTP..."
    
    log_info "Deteniendo servicios..."
    systemctl stop apache2 nginx tomcat* 2>/dev/null || true
    systemctl disable apache2 nginx tomcat* 2>/dev/null || true
    
    log_info "Eliminando paquetes..."
    apt-get purge -y apache2 apache2-utils nginx nginx-common tomcat9 tomcat9-common default-jdk 2>/dev/null || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    
    log_info "Limpiando archivos de configuración y datos..."
    rm -rf /etc/apache2 /etc/nginx /etc/tomcat*
    rm -rf /var/www/html/*
    rm -rf /opt/tomcat*
    rm -f /etc/systemd/system/tomcat*.service
    systemctl daemon-reload
    
    log_info "Eliminando usuarios de servicio..."
    userdel -r tomcat 2>/dev/null || true
    
    log_success "Purga completada."
}

# ==============================================================================
# MAIN
# ==============================================================================

show_help() {
    echo "Uso: $0 --service <apache|nginx|tomcat> --port <num> [--version <ver>]"
}

main() {
    local service=""
    local port=0
    local version=""
    local list_v=false
    local status=false
    local purge=false

    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --service) service="${2,,}"; shift ;;
            --port) port="$2"; shift ;;
            --version) version="$2"; shift ;;
            --list-versions) list_v=true ;;
            --status) status=true ;;
            --purge) purge=true ;;
            -h|--help) show_help; exit 0 ;;
        esac
        shift
    done

    if $status; then
        systemctl status apache2 nginx tomcat9 --no-pager 2>/dev/null || true
        exit 0
    fi

    if $purge; then
        wait_for_apt_lock
        purge_services
        exit 0
    fi

    if [[ -z "$service" ]]; then show_help; exit 1; fi
    check_root

    if $list_v; then
        log_info "Versiones para $service:"
        if [[ "$service" == "tomcat" ]]; then
            echo "10.1.34 (Stable)"
            echo "9.0.98 (LTS)"
        else
            apt-cache madison ${service/apache/apache2} | awk '{print $3}' | head -n 5
        fi
        exit 0
    fi

    if [[ "$port" -eq 0 ]]; then log_error "Puerto es obligatorio"; fi
    
    wait_for_apt_lock
    case $service in
        apache) install_apache "$port" "${version:-2.4.58}" ;;
        nginx)  install_nginx "$port" "${version:-1.24.0}" ;;
        tomcat) install_tomcat "$port" "${version:-9.0.98}" ;;
        *) log_error "Servicio no soportado" ;;
    esac

    configure_firewall "$port"
    log_success "Despliegue de $service finalizado correctamente."
}

main "$@"

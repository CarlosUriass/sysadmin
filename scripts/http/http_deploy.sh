#!/bin/bash
# ==============================================================================
# Script: http_deploy.sh
# description: Despliegue dinámico y hardening HTTP (Práctica 6)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        log_warn "El sistema está realizando actualizaciones en segundo plano. Esperando 5 segundos..."
        sleep 5
    done
}

configure_firewall() {
    local port=$1
    log_info "Configurando Firewall (UFW)..."
    if command -v ufw >/dev/null; then
        ufw allow "$port"/tcp comment "HTTP Practice 6" >/dev/null
        log_info "Puerto $port habilitado en UFW."
    fi
}

create_service_user() {
    local user=$1
    local dir=$2
    if ! id "$user" &>/dev/null; then
        useradd -r -s /usr/sbin/nologin "$user"
    fi
    mkdir -p "$dir"
    chown -R "$user":"$user" "$dir"
    chmod -R 755 "$dir"
    log_info "Usuario dedicado '$user' configurado para el directorio $dir"
}

# Instala paquetes SIN policy-rc.d para que apt pueda iniciar servicios
# y depositar todos los archivos de configuracion correctamente
apt_install_safe() {
    rm -f /usr/sbin/policy-rc.d
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    if ! apt-get install -y -qq "$@"; then
        log_warn "Instalacion interrumpida, intentando reparar..."
        apt-get install -f -y -qq
        apt-get install -y -qq --reinstall "$@"
    fi
}

# ==============================================================================
# INSTALLATION LOGIC
# ==============================================================================

generate_index() {
    local path=$1 srv=$2 ver=$3 port=$4
    mkdir -p "$(dirname "$path")"
    cat > "$path" <<EOF
<html><body>
<h1>Servidor: $srv - Version: $ver - Puerto: $port</h1>
<p>Aprovisionamiento Automatizado - Linux (Practica 6)</p>
<p>Fecha: $(date)</p>
</body></html>
EOF
}

# ------------------------------------------------------------------------------
install_apache() {
    local p=$1
    local ver=$2
    check_port "$p"
    log_info "Instalando Apache..."

    # Instalar sin policy-rc.d para que apt deposite todos los archivos
    apt_install_safe apache2 apache2-utils apache2-bin apache2-data

    # Verificar que los archivos esenciales existen tras la instalacion
    if [[ ! -f "/etc/apache2/ports.conf" ]] || [[ ! -f "/etc/apache2/apache2.conf" ]]; then
        log_warn "Archivos de configuracion faltantes tras apt. Recreando estructura..."

        mkdir -p /etc/apache2/mods-enabled \
                 /etc/apache2/mods-available \
                 /etc/apache2/sites-enabled \
                 /etc/apache2/sites-available \
                 /etc/apache2/conf-enabled \
                 /etc/apache2/conf-available \
                 /var/www/html \
                 /var/log/apache2 \
                 /var/run/apache2

        cat > /etc/apache2/ports.conf <<'EOF'
Listen 80
<IfModule ssl_module>
    Listen 443
</IfModule>
<IfModule mod_gnutls.c>
    Listen 443
</IfModule>
EOF

        cat > /etc/apache2/apache2.conf <<'EOF'
DefaultRuntimeDir /var/run/apache2
PidFile /var/run/apache2/apache2.pid
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User www-data
Group www-data
HostnameLookups Off
ErrorLog /var/log/apache2/error.log
LogLevel warn
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
Include ports.conf
<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>
<Directory /var/www/html>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
EOF

        cat > /etc/apache2/envvars <<'EOF'
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
export APACHE_PID_FILE=/var/run/apache2/apache2.pid
export APACHE_RUN_DIR=/var/run/apache2
export APACHE_LOCK_DIR=/var/lock/apache2
export APACHE_LOG_DIR=/var/log/apache2
export LANG=C
EOF

        cat > /etc/apache2/sites-available/000-default.conf <<'EOF'
<VirtualHost *:80>
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
        ln -sf /etc/apache2/sites-available/000-default.conf \
               /etc/apache2/sites-enabled/000-default.conf 2>/dev/null || true
    fi

    # Ajustar puerto
    sed -i "s/Listen 80/Listen $p/" /etc/apache2/ports.conf
    sed -i "s/<VirtualHost \*:80>/<VirtualHost *:$p>/" \
        /etc/apache2/sites-available/000-default.conf 2>/dev/null || true

    # Hardening
    if [[ -f "/etc/apache2/conf-available/security.conf" ]]; then
        sed -i "s/ServerTokens .*/ServerTokens Prod/" /etc/apache2/conf-available/security.conf
        sed -i "s/ServerSignature .*/ServerSignature Off/" /etc/apache2/conf-available/security.conf
        a2enconf security >/dev/null 2>&1 || true
    fi

    a2enmod headers >/dev/null 2>&1 || true

    grep -q "X-Frame-Options" /etc/apache2/apache2.conf || \
        echo "Header set X-Frame-Options SAMEORIGIN" >> /etc/apache2/apache2.conf
    grep -q "X-Content-Type-Options" /etc/apache2/apache2.conf || \
        echo "Header set X-Content-Type-Options nosniff" >> /etc/apache2/apache2.conf

    if ! grep -q "LimitExcept" /etc/apache2/apache2.conf; then
        cat >> /etc/apache2/apache2.conf <<'EOF'
<Directory /var/www/html/>
    <LimitExcept GET POST>
        Deny from all
    </LimitExcept>
</Directory>
EOF
    fi

    # Validar antes de arrancar
    local test_out
    test_out=$(apache2ctl configtest 2>&1) || log_error "Configuracion Apache invalida:\n$test_out"

    generate_index "/var/www/html/index.html" "Apache" "$ver" "$p"
    create_service_user "www-data" "/var/www/html"

    systemctl enable apache2 2>/dev/null || true
    systemctl restart apache2 || log_error "No se pudo iniciar apache2. Revisa: journalctl -xeu apache2.service"
}

# ------------------------------------------------------------------------------
install_nginx() {
    local p=$1
    local ver=$2
    check_port "$p"
    log_info "Instalando Nginx..."

    apt_install_safe nginx

    # Asegurar directorios necesarios
    mkdir -p /etc/nginx/sites-available \
             /etc/nginx/sites-enabled \
             /etc/nginx/conf.d \
             /etc/nginx/modules-enabled \
             /var/log/nginx \
             /var/lib/nginx/body \
             /run/nginx

    # mime.types minimo si no existe
    if [[ ! -f "/etc/nginx/mime.types" ]]; then
        log_warn "mime.types no encontrado. Creando version minima..."
        cat > /etc/nginx/mime.types <<'EOF'
types {
    text/html                   html htm shtml;
    text/css                    css;
    text/plain                  txt;
    application/javascript      js;
    application/json            json;
    image/png                   png;
    image/jpeg                  jpeg jpg;
    image/gif                   gif;
    image/svg+xml               svg svgz;
    image/x-icon                ico;
    font/woff                   woff;
    font/woff2                  woff2;
    application/octet-stream    bin;
}
EOF
    fi

    local nginx_conf="/etc/nginx/nginx.conf"

    # nginx.conf sin include modules-enabled (evita fallos por .so faltantes)
    if [[ ! -f "$nginx_conf" ]]; then
        log_warn "nginx.conf no encontrado. Creando configuracion basica..."
        cat > "$nginx_conf" <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;

    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
        log_info "nginx.conf creado manualmente."
    else
        # Hardening idempotente sobre conf existente
        sed -i "s/# server_tokens off;/server_tokens off;/" "$nginx_conf" 2>/dev/null || true
        if ! grep -q "X-Frame-Options" "$nginx_conf"; then
            sed -i "/http {/a\\    add_header X-Frame-Options SAMEORIGIN;\n    add_header X-Content-Type-Options nosniff;" "$nginx_conf"
        fi
    fi

    # Site default con puerto objetivo directo
    local conf="/etc/nginx/sites-available/default"
    cat > "$conf" <<EOF
server {
    listen $p default_server;
    listen [::]:$p default_server;
    root /var/www/html;
    index index.html index.htm;
    server_name _;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    ln -sf "$conf" /etc/nginx/sites-enabled/default 2>/dev/null || true

    generate_index "/var/www/html/index.html" "Nginx" "$ver" "$p"
    create_service_user "www-data" "/var/www/html"

    # Validar antes de arrancar
    local test_out
    test_out=$(nginx -t 2>&1) || log_error "Configuracion Nginx invalida:\n$test_out"

    systemctl enable nginx 2>/dev/null || true
    systemctl restart nginx || log_error "No se pudo iniciar nginx. Revisa: journalctl -xeu nginx.service"
}

# ------------------------------------------------------------------------------
install_tomcat() {
    local p=$1
    local ver=$2
    check_port "$p"
    log_info "Instalando Tomcat $ver (Binario)..."

    apt_install_safe default-jdk wget tar

    local major
    major=$(echo "$ver" | cut -d. -f1)
    local url="https://archive.apache.org/dist/tomcat/tomcat-$major/v$ver/bin/apache-tomcat-$ver.tar.gz"
    local dest="/opt/tomcat${major}"

    if [[ ! -d "$dest" ]]; then
        mkdir -p "$dest"
        wget -qO /tmp/tomcat.tar.gz "$url"
        tar -xzf /tmp/tomcat.tar.gz -C "$dest" --strip-components=1
        rm -f /tmp/tomcat.tar.gz
    fi

    sed -i "s/port=\"8080\"/port=\"$p\"/" "$dest/conf/server.xml"

    generate_index "$dest/webapps/ROOT/index.html" "Tomcat" "$ver" "$p"
    create_service_user "tomcat" "$dest"

    cat > /etc/systemd/system/tomcat${major}.service <<EOF
[Unit]
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
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable tomcat${major} --now || \
        log_error "No se pudo iniciar tomcat${major}. Revisa: journalctl -xeu tomcat${major}.service"
}

# ------------------------------------------------------------------------------
purge_services() {
    check_root
    log_warn "Iniciando purga total de servicios HTTP..."

    log_info "Deteniendo servicios..."
    systemctl stop apache2 nginx tomcat* 2>/dev/null || true
    systemctl disable apache2 nginx tomcat* 2>/dev/null || true

    log_info "Eliminando paquetes..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y apache2 apache2-utils apache2-bin apache2-data \
        nginx nginx-common nginx-core \
        tomcat9 tomcat9-common default-jdk 2>/dev/null || true
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
    echo ""
    echo "Opciones:"
    echo "  --service   <apache|nginx|tomcat>  Servidor a instalar"
    echo "  --port      <num>                  Puerto de escucha"
    echo "  --version   <ver>                  Version específica (opcional)"
    echo "  --list-versions                    Listar versiones disponibles"
    echo "  --status                           Ver estado de los servicios"
    echo "  --purge                            Eliminar todos los servicios instalados"
    echo "  -h, --help                         Mostrar esta ayuda"
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
            --service)       service="${2,,}"; shift ;;
            --port)          port="$2";        shift ;;
            --version)       version="$2";     shift ;;
            --list-versions) list_v=true ;;
            --status)        status=true ;;
            --purge)         purge=true ;;
            -h|--help)       show_help; exit 0 ;;
            *) log_warn "Argumento desconocido: $1" ;;
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
        log_info "Versiones disponibles para $service:"
        if [[ "$service" == "tomcat" ]]; then
            echo "10.1.34 (Stable)"
            echo "9.0.98  (LTS)"
        else
            apt-cache madison "${service/apache/apache2}" | awk '{print $3}' | head -n 5
        fi
        exit 0
    fi

    if [[ "$port" -eq 0 ]]; then log_error "Puerto es obligatorio (--port <num>)"; fi

    wait_for_apt_lock

    case $service in
        apache) install_apache "$port" "${version:-2.4.58}" ;;
        nginx)  install_nginx  "$port" "${version:-1.24.0}" ;;
        tomcat) install_tomcat "$port" "${version:-9.0.98}" ;;
        *) log_error "Servicio no soportado: $service" ;;
    esac

    configure_firewall "$port"
    log_success "Despliegue de $service en puerto $port finalizado correctamente."
}

main "$@"
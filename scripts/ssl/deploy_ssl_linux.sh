#!/bin/bash
# ==============================================================================
# Script: deploy_ssl_linux.sh
# Descripción: Aprovisionamiento híbrido (Web/FTP), cifrado SSL/TLS y
#              validación de integridad (Práctica 7)
# ==============================================================================
set -euo pipefail

# ==============================================================================
# VARIABLES GLOBALES
# ==============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FTP_SERVER="192.168.100.11"
FTP_USER="usuario"
FTP_PASS="pass"
DOMAIN="www.reprobados.com"
CERT_DIR="/etc/ssl/reprobados"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"

# ==============================================================================
# LOGGING & UTILIDADES
# ==============================================================================
log_info() { echo -e "\e[34m[INFO]\e[0m $1"; }
log_success() { echo -e "\e[32m[OK]\e[0m $1"; }
log_warn() { echo -e "\e[33m[WARN]\e[0m $1"; }
log_error() { echo -e "\e[31m[ERROR]\e[0m $1" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (sudo)."
        exit 1
    fi
}

wait_for_apt_lock() {
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        log_warn "Apt bloqueado. Esperando 5s..."
        sleep 5
    done
}

# ==============================================================================
# LÓGICA DE SSL/TLS
# ==============================================================================
generate_ssl_cert() {
    if [[ ! -d "$CERT_DIR" ]]; then
        mkdir -p "$CERT_DIR"
    fi

    if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
        log_info "Generando certificado autofirmado para $DOMAIN..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$KEY_FILE" -out "$CERT_FILE" \
            -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=UAS/OU=FIM/CN=$DOMAIN" 2>/dev/null
        chmod 600 "$KEY_FILE"
        chmod 644 "$CERT_FILE"
        log_success "Certificado SSL generado."
    else
        log_info "El certificado SSL ya existe. Reutilizando."
    fi
}

ask_ssl() {
    local svc=$1
    echo -ne "\e[33m¿Desea activar SSL en el servicio $svc? [S/N] \e[0m"
    read -r resp
    if [[ "$resp" == "S" || "$resp" == "s" ]]; then
        generate_ssl_cert
        return 0
    else
        return 1
    fi
}

ask_ports() {
    local svc=$1
    local default_http=$2
    local default_https=$3

    echo -ne "Ingrese el puerto HTTP deseado para $svc [default: $default_http]: "
    read -r p_http
    PORT_HTTP=${p_http:-$default_http}

    if [[ ${enable_ssl:-0} -eq 1 ]]; then
        echo -ne "Ingrese el puerto HTTPS (SSL) deseado para $svc [default: $default_https]: "
        read -r p_https
        PORT_HTTPS=${p_https:-$default_https}
    else
        PORT_HTTPS=$default_https
    fi
}

# ==============================================================================
# LÓGICA FTP Y HASH (Integridad)
# ==============================================================================
download_from_ftp() {
    local service=$1
    local kind=$2   # "http" o "ftp" dependiento del servicio para la ruta
    local os="Linux"
    local base_url="ftp://${FTP_SERVER}/${kind}/${os}/${service}"

    log_info "Conectando al FTP para buscar versiones de $service..."
    
    # Listar archivos disponibles
    local files
    if ! files=$(curl -u "${FTP_USER}:${FTP_PASS}" "${base_url}/" -s --list-only); then
        log_error "No se pudo conectar al repositorio FTP o la ruta no existe."
        return 1
    fi

    local installers=()
    for f in $files; do
        if [[ "$f" != *.sha256 && "$f" != *.md5 ]]; then
            installers+=("$f")
        fi
    done

    if [[ ${#installers[@]} -eq 0 ]]; then
        log_error "No se encontraron instaladores en el FTP para $service."
        return 1
    fi

    echo "Versiones disponibles para $service:"
    local i=1
    for inst in "${installers[@]}"; do
        echo "$i) $inst"
        ((i++))
    done

    echo -ne "Seleccione el número del archivo a descargar: "
    read -r sel
    if [[ ! "$sel" =~ ^[0-9]+$ || "$sel" -lt 1 || "$sel" -gt ${#installers[@]} ]]; then
        log_error "Selección inválida."
        return 1
    fi

    local chosen="${installers[$((sel - 1))]}"
    local local_file="/tmp/$chosen"
    local hash_file="${local_file}.sha256"

    log_info "Descargando $chosen desde FTP..."
    curl -u "${FTP_USER}:${FTP_PASS}" "${base_url}/${chosen}" -o "$local_file" -s

    log_info "Descargando comprobación de hash (${chosen}.sha256)..."
    if curl -u "${FTP_USER}:${FTP_PASS}" "${base_url}/${chosen}.sha256" -o "$hash_file" -s -f; then
        log_info "Verificando integridad del archivo..."
        local expected_hash=$(awk '{print $1}' "$hash_file")
        local actual_hash=$(sha256sum "$local_file" | awk '{print $1}')
        
        if [[ "$expected_hash" == "$actual_hash" ]]; then
            log_success "Verificación Hash exitosa (SHA256 coincide)."
        else
            log_error "Fallo en verificación de Hash. El archivo puede estar corrupto."
            rm -f "$local_file" "$hash_file"
            return 1
        fi
    else
        log_warn "No se encontró archivo de hash .sha256 en el servidor. Saltando verificación."
    fi

    echo "$local_file"
    return 0
}

# ==============================================================================
# INSTALACIONES ESPECÍFICAS
# ==============================================================================
install_apache_ssl() {
    log_info "Iniciando instalación de Apache..."
    local source=$1
    enable_ssl=0
    if ask_ssl "Apache"; then enable_ssl=1; fi

    ask_ports "Apache" "80" "443"

    log_info "Instalando servicio Apache base a través de http_deploy.sh (Puerto: $PORT_HTTP)..."
    # Invocar al script de la Práctica 6 con los argumentos correctos
    bash "$SCRIPT_DIR/../http/http_deploy.sh" --service apache --port "$PORT_HTTP"

    # El script instalará Apache por apt (según su lógica default de Web) y lo dejará puro
    # Ahora configuramos el SSL encima

    if [[ $enable_ssl -eq 1 ]]; then
        # Aseguramos dependencias extra de certificados por si http_deploy no las puso
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y ssl-cert apache2-utils >/dev/null 2>&1 || true
        log_info "Configurando SSL y forzando HSTS en Apache..."
        
        # Limpiar symlinks rotos previos
        find /etc/apache2/mods-enabled/ -xtype l -delete

        # Activar los módulos de forma limpia
        a2enmod ssl
        a2enmod rewrite
        a2enmod headers
        a2enmod socache_shmcb

        # VirtualHost HTTP: Redirect to https
        cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:$PORT_HTTP>
    ServerName $DOMAIN
    Redirect permanent / https://$FTP_SERVER:$PORT_HTTPS/
</VirtualHost>
EOF

        # VirtualHost HTTPS
        cat <<EOF > /etc/apache2/sites-available/default-ssl.conf
<VirtualHost _default_:$PORT_HTTPS>
    ServerName $DOMAIN
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile    $CERT_FILE
    SSLCertificateKeyFile $KEY_FILE

    Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains;"
</VirtualHost>
EOF
        # Habilitar el sitio
        a2ensite default-ssl || true
    fi

    systemctl restart apache2
    systemctl enable apache2
    log_success "Apache instalado y configurado."
}

install_nginx_ssl() {
    log_info "Iniciando instalación de Nginx..."
    local source=$1
    enable_ssl=0
    if ask_ssl "Nginx"; then enable_ssl=1; fi

    ask_ports "Nginx" "80" "443"

    log_info "Instalando servicio Nginx base a través de http_deploy.sh (Puerto: $PORT_HTTP)..."
    bash "$SCRIPT_DIR/../http/http_deploy.sh" --service nginx --port "$PORT_HTTP"

    if [[ $enable_ssl -eq 1 ]]; then
        log_info "Configurando SSL y forzando HSTS en Nginx..."
        cat <<EOF > /etc/nginx/sites-available/default
server {
    listen $PORT_HTTP default_server;
    listen [::]:$PORT_HTTP default_server;
    server_name $DOMAIN;
    return 301 https://$FTP_SERVER:$PORT_HTTPS\$request_uri;
}

server {
    listen $PORT_HTTPS ssl http2 default_server;
    listen [::]:$PORT_HTTPS ssl http2 default_server;
    server_name $DOMAIN;

    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;

    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains" always;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
}
EOF
    fi

    systemctl restart nginx
    systemctl enable nginx
    log_success "Nginx instalado y configurado."
}

install_tomcat_ssl() {
    log_info "Iniciando instalación de Tomcat..."
    local source=$1

    enable_ssl=0
    if ask_ssl "Tomcat"; then enable_ssl=1; fi
    
    ask_ports "Tomcat" "8080" "8443"

    log_info "Instalando servicio Tomcat base a través de http_deploy.sh (Puerto: $PORT_HTTP)..."
    bash "$SCRIPT_DIR/../http/http_deploy.sh" --service tomcat --port "$PORT_HTTP"

    if [[ $enable_ssl -eq 1 ]]; then
        log_info "Configurando SSL en Tomcat (generando Keystore desde PEM)..."
        # Tomcat requiere keystore. Convertimos PEM a PKCS12
        local pkcs12_file="${CERT_DIR}/tomcat.p12"
        openssl pkcs12 -export -in "$CERT_FILE" -inkey "$KEY_FILE" -out "$pkcs12_file" -name tomcat -password pass:changeit 2>/dev/null
        
        # En caso de instalación apt:
        if [[ "$source" != "FTP" ]]; then
            # Modificar server.xml de tomcat9
            local txt_insert='<Connector port="'$PORT_HTTPS'" protocol="org.apache.coyote.http11.Http11NioProtocol" maxThreads="150" SSLEnabled="true" scheme="https" secure="true" keystoreFile="'$pkcs12_file'" keystorePass="changeit" clientAuth="false" sslProtocol="TLS" />'
            sed -i '/<Service name="Catalina">/a '"$txt_insert"'' /etc/tomcat9/server.xml
            systemctl restart tomcat9
        else
            # Modificar server.xml de tomcat tarball
            local txt_insert='<Connector port="'$PORT_HTTPS'" protocol="org.apache.coyote.http11.Http11NioProtocol" maxThreads="150" SSLEnabled="true" scheme="https" secure="true" keystoreFile="'$pkcs12_file'" keystorePass="changeit" clientAuth="false" sslProtocol="TLS" />'
            sed -i '/<Service name="Catalina">/a '"$txt_insert"'' /opt/tomcat/conf/server.xml
            /opt/tomcat/bin/catalina.sh start
        fi
    fi
    log_success "Tomcat instalado y configurado."
}

install_vsftpd_ssl() {
    log_info "Iniciando instalación de vsftpd..."
    local source=$1
    if [[ "$source" == "FTP" ]]; then
        local package_path
        package_path=$(download_from_ftp "vsftpd" "ftp") || return 1
        wait_for_apt_lock
        dpkg -i "$package_path" || apt-get install -f -y
    else
        wait_for_apt_lock
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y vsftpd -qq
    fi

    local enable_ssl=0
    if ask_ssl "vsftpd"; then enable_ssl=1; fi

    if [[ $enable_ssl -eq 1 ]]; then
        log_info "Configurando SSL (FTPS explícito) en vsftpd..."
        cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
        sed -i 's/^ssl_enable=.*/ssl_enable=YES/' /etc/vsftpd.conf || echo "ssl_enable=YES" >> /etc/vsftpd.conf
        sed -i 's,^rsa_cert_file=.*,rsa_cert_file='"$CERT_FILE"',' /etc/vsftpd.conf || echo "rsa_cert_file=$CERT_FILE" >> /etc/vsftpd.conf
        sed -i 's,^rsa_private_key_file=.*,rsa_private_key_file='"$KEY_FILE"',' /etc/vsftpd.conf || echo "rsa_private_key_file=$KEY_FILE" >> /etc/vsftpd.conf
        grep -q "^allow_anon_ssl=" /etc/vsftpd.conf || echo "allow_anon_ssl=NO" >> /etc/vsftpd.conf
        grep -q "^force_local_data_ssl=" /etc/vsftpd.conf || echo "force_local_data_ssl=YES" >> /etc/vsftpd.conf
        grep -q "^force_local_logins_ssl=" /etc/vsftpd.conf || echo "force_local_logins_ssl=YES" >> /etc/vsftpd.conf
        grep -q "^require_ssl_reuse=" /etc/vsftpd.conf || echo "require_ssl_reuse=NO" >> /etc/vsftpd.conf
        grep -q "^ssl_ciphers=" /etc/vsftpd.conf || echo "ssl_ciphers=HIGH" >> /etc/vsftpd.conf
        grep -q "^seccomp_sandbox=" /etc/vsftpd.conf || echo "seccomp_sandbox=NO" >> /etc/vsftpd.conf
        grep -q "^strict_ssl_read_eof=" /etc/vsftpd.conf || echo "strict_ssl_read_eof=NO" >> /etc/vsftpd.conf
    fi

    systemctl restart vsftpd
    systemctl enable vsftpd
    log_success "vsftpd instalado y configurado."
}

# ==============================================================================
# MAIN
# ==============================================================================
main() {
    check_root

    echo "============================================================"
    echo "  ORQUESTADOR DE DESPLIEGUE HÍBRIDO CON SSL/TLS (Práctica 7)"
    echo "============================================================"
    echo "Servicios disponibles para instalar en Linux:"
    echo "  1) Apache (HTTP)"
    echo "  2) Nginx (HTTP)"
    echo "  3) Tomcat (HTTP)"
    echo "  4) vsftpd (FTP)"
    echo -ne "Seleccione un servicio (1-4): "
    read -r s_opt

    local svc=""
    case "$s_opt" in
        1) svc="apache" ;;
        2) svc="nginx" ;;
        3) svc="tomcat" ;;
        4) svc="vsftpd" ;;
        *) log_error "Opción inválida."; exit 1 ;;
    esac

    echo "============================================================"
    echo "Fuente de Instalación para $svc:"
    echo "  1) WEB (Gestor de Paquetes APT oficial)"
    echo "  2) FTP (Repositorio Privado con validación SHA256)"
    echo -ne "Seleccione fuente (1-2): "
    read -r m_opt

    local source=""
    case "$m_opt" in
        1) source="WEB" ;;
        2) source="FTP" ;;
        *) log_error "Opción inválida."; exit 1 ;;
    esac

    echo "============================================================"
    log_info "Instalando $svc mediante $source..."

    case "$svc" in
        "apache") install_apache_ssl "$source" ;;
        "nginx")  install_nginx_ssl "$source" ;;
        "tomcat") install_tomcat_ssl "$source" ;;
        "vsftpd") install_vsftpd_ssl "$source" ;;
    esac

    echo "============================================================"
    log_info "Resumen de Instalación Asegurada:"
    ss -tlnp | grep -E ":80|:443|:8443|:21|:990" || true
    log_success "Proceso de orquestación completado."
}

main "$@"

#!/bin/bash
# ==============================================================================
# Práctica 6 - Despliegue Dinámico de Servicios HTTP Multi-Versión
# Sistema Operativo: Linux (Ubuntu/Debian)
# Uso interactivo: sudo bash http_deploy.sh
# Uso con parámetros: sudo bash http_deploy.sh -s apache2 -p 8080
# ==============================================================================

# Directorios de utilidades
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
UTILS_SH_DIR="$(readlink -f "$SCRIPT_DIR/../utils/sh")"
UTILS_LOG_DIR="$(readlink -f "$SCRIPT_DIR/../utils/logs")"

# Importar logger
if [[ -f "$UTILS_LOG_DIR/logger.sh" ]]; then
    source "$UTILS_LOG_DIR/logger.sh"
else
    echo "ERROR: No se encontró el script logger.sh en $UTILS_LOG_DIR"
    exit 1
fi

# ==============================================================================
# VERIFICAR ROOT
# ==============================================================================
if [[ $EUID -ne 0 ]]; then
    log_error "Este script debe ejecutarse como root o con sudo."
fi

# ==============================================================================
# VERIFICAR CONECTIVIDAD Y ACTUALIZAR REPOS
# ==============================================================================
verificar_conectividad() {
    log_info "Verificando conectividad y actualizando repositorios..."
    if ! ping -c 1 -W 3 8.8.8.8 &>/dev/null; then
        log_error "Sin conexión a internet. El script requiere acceso a repositorios."
    fi
    apt-get update -qq 2>/dev/null
}

# ==============================================================================
# FUNCIÓN: VALIDAR PUERTO
# ==============================================================================
validar_puerto_ext() {
    local puerto=$1

    # Usar las utilidades de línea de comandos para validación
    "$UTILS_SH_DIR/validate_port.sh" --port "$puerto" >/dev/null 2>&1
    local validation_status=$?

    if [[ $validation_status -ne 0 ]]; then
        log_error "El puerto $puerto es inválido o está reservado (1-1023)."
        return 1
    fi

    # Verificar si está en uso
    "$UTILS_SH_DIR/check_port_in_use.sh" --port "$puerto" >/dev/null 2>&1
    local in_use_status=$?
    
    # check_port_in_use retorna 0 si ESTA EN USO, 1 si no lo esta
    if [[ $in_use_status -eq 0 ]]; then
        local proceso=$(ss -tlnp 2>/dev/null | grep ":${puerto} " | awk '{print $NF}' | head -1)
        log_error "El puerto $puerto ya está en uso por: $proceso"
        return 1
    fi

    return 0
}

# ==============================================================================
# FUNCIÓN: PEDIR PUERTO AL USUARIO
# ==============================================================================
pedir_puerto() {
    local puerto_input
    while true; do
        echo -e "\e[0;36mIngresa el puerto de escucha (ej: 8080, 8888):\e[0m "
        read -r puerto_input

        # Validar no vacío
        if [[ -z "$puerto_input" ]]; then
            log_warn "El puerto no puede estar vacío."
            continue
        fi

        # Eliminar caracteres no numéricos por seguridad
        puerto_input=$(echo "$puerto_input" | tr -cd '0-9')

        if validar_puerto_ext "$puerto_input" 2>/dev/null; then
            PUERTO_ELEGIDO="$puerto_input"
            log_success "Puerto $PUERTO_ELEGIDO aceptado."
            break
        fi
    done
}

# ==============================================================================
# FUNCIONES: OBTENER VERSIONES
# ==============================================================================
obtener_versiones_apache() {
    log_info "Consultando versiones disponibles de Apache2..."
    mapfile -t VERSIONES_APACHE < <(apt-cache madison apache2 2>/dev/null | awk '{print $3}' | sort -u)

    if [[ ${#VERSIONES_APACHE[@]} -eq 0 ]]; then
        log_error "No se encontraron versiones de Apache2 en los repositorios."
        return 1
    fi

    echo -e "\e[1mVersiones disponibles de Apache2:\e[0m"
    for i in "${!VERSIONES_APACHE[@]}"; do
        local etiqueta=""
        if [[ $i -eq 0 ]]; then etiqueta="\e[0;32m(Estable/LTS)\e[0m"; fi
        if [[ $i -eq $((${#VERSIONES_APACHE[@]}-1)) && $i -ne 0 ]]; then etiqueta="\e[1;33m(Latest)\e[0m"; fi
        echo -e "  \e[1m$((i+1)))\e[0m ${VERSIONES_APACHE[$i]} $etiqueta"
    done

    # Si estamos en modo no interactivo, tomamos la ultima por defecto.
    if [[ "$INTERACTIVO" -eq 0 ]]; then
        VERSION_ELEGIDA="${VERSIONES_APACHE[$((${#VERSIONES_APACHE[@]}-1))]}"
        return 0
    fi

    local seleccion
    while true; do
        echo -e "\e[0;36mSelecciona una versión [1-${#VERSIONES_APACHE[@]}]:\e[0m "
        read -r seleccion
        seleccion=$(echo "$seleccion" | tr -cd '0-9')
        if [[ "$seleccion" -ge 1 && "$seleccion" -le ${#VERSIONES_APACHE[@]} ]]; then
            VERSION_ELEGIDA="${VERSIONES_APACHE[$((seleccion-1))]}"
            log_success "Versión seleccionada: $VERSION_ELEGIDA"
            return 0
        fi
        log_warn "Selección inválida. Ingresa un número entre 1 y ${#VERSIONES_APACHE[@]}."
    done
}

obtener_versiones_nginx() {
    log_info "Consultando versiones disponibles de Nginx..."
    mapfile -t VERSIONES_NGINX < <(apt-cache madison nginx 2>/dev/null | awk '{print $3}' | sort -u)

    if [[ ${#VERSIONES_NGINX[@]} -eq 0 ]]; then
        log_error "No se encontraron versiones de Nginx en los repositorios."
        return 1
    fi

    echo -e "\e[1mVersiones disponibles de Nginx:\e[0m"
    for i in "${!VERSIONES_NGINX[@]}"; do
        local etiqueta=""
        if [[ $i -eq 0 ]]; then etiqueta="\e[0;32m(Estable/LTS)\e[0m"; fi
        if [[ $i -eq $((${#VERSIONES_NGINX[@]}-1)) && $i -ne 0 ]]; then etiqueta="\e[1;33m(Latest)\e[0m"; fi
        echo -e "  \e[1m$((i+1)))\e[0m ${VERSIONES_NGINX[$i]} $etiqueta"
    done

    # Si estamos en modo no interactivo, tomamos la ultima por defecto.
    if [[ "$INTERACTIVO" -eq 0 ]]; then
        VERSION_ELEGIDA="${VERSIONES_NGINX[$((${#VERSIONES_NGINX[@]}-1))]}"
        return 0
    fi

    local seleccion
    while true; do
        echo -e "\e[0;36mSelecciona una versión [1-${#VERSIONES_NGINX[@]}]:\e[0m "
        read -r seleccion
        seleccion=$(echo "$seleccion" | tr -cd '0-9')
        if [[ "$seleccion" -ge 1 && "$seleccion" -le ${#VERSIONES_NGINX[@]} ]]; then
            VERSION_ELEGIDA="${VERSIONES_NGINX[$((seleccion-1))]}"
            log_success "Versión seleccionada: $VERSION_ELEGIDA"
            return 0
        fi
        log_warn "Selección inválida."
    done
}

obtener_versiones_tomcat() {
    log_info "Consultando versiones disponibles de Tomcat..."

    # Verificar Java e instalar con el util de paquetes
    if ! command -v java &>/dev/null; then
        log_warn "Java no encontrado. Instalando OpenJDK 17..."
        apt-get install -y -qq openjdk-17-jdk 2>/dev/null
        if ! command -v java &>/dev/null; then
            log_error "No se pudo instalar Java. Tomcat requiere Java."
            return 1
        fi
    fi
    log_success "Java disponible: $(java -version 2>&1 | head -1)"

    declare -gA TOMCAT_VERSIONES=( ["1"]="9.0.98" ["2"]="10.1.39" ["3"]="11.0.4" )
    declare -gA TOMCAT_RAMAS=( ["1"]="9" ["2"]="10" ["3"]="11" )

    echo -e "\e[1mVersiones disponibles de Tomcat:\e[0m"
    echo -e "  \e[1m1)\e[0m Tomcat ${TOMCAT_VERSIONES[1]} \e[0;32m(Rama 9 - LTS, Java 8+)\e[0m"
    echo -e "  \e[1m2)\e[0m Tomcat ${TOMCAT_VERSIONES[2]} \e[1;33m(Rama 10 - Estable, Java 11+)\e[0m"
    echo -e "  \e[1m3)\e[0m Tomcat ${TOMCAT_VERSIONES[3]} \e[1;33m(Rama 11 - Latest, Java 17+)\e[0m"

    if [[ "$INTERACTIVO" -eq 0 ]]; then
        # Tomcat 11 by default
        VERSION_ELEGIDA="${TOMCAT_VERSIONES[3]}"
        TOMCAT_RAMA="${TOMCAT_RAMAS[3]}"
        return 0
    fi

    local seleccion
    while true; do
        echo -e "\e[0;36mSelecciona una versión [1-3]:\e[0m "
        read -r seleccion
        seleccion=$(echo "$seleccion" | tr -cd '0-9')
        if [[ "$seleccion" -ge 1 && "$seleccion" -le 3 ]]; then
            VERSION_ELEGIDA="${TOMCAT_VERSIONES[$seleccion]}"
            TOMCAT_RAMA="${TOMCAT_RAMAS[$seleccion]}"
            log_success "Versión seleccionada: Tomcat $VERSION_ELEGIDA"
            return 0
        fi
        log_warn "Selección inválida. Ingresa 1, 2 o 3."
    done
}

# ==============================================================================
# INSTALACIÓN DE SERVICIOS
# ==============================================================================
instalar_apache() {
    echo -e "\n\e[1m═══════════════════════════════════════\e[0m"
    echo -e "\e[1m  Instalando Apache2\e[0m"
    echo -e "\e[1m═══════════════════════════════════════\e[0m"

    obtener_versiones_apache || return 1
    if [[ -z "$PUERTO_ELEGIDO" ]]; then pedir_puerto; fi

    log_info "Instalando Apache2 versión $VERSION_ELEGIDA..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 2>/dev/null
    if [[ $? -ne 0 ]]; then
        log_error "Falló la instalación de Apache2."
    fi

    log_info "Configurando puerto $PUERTO_ELEGIDO en Apache..."
    sed -i "s/Listen [0-9]*/Listen $PUERTO_ELEGIDO/g" /etc/apache2/ports.conf
    sed -i "s/<VirtualHost \*:[0-9]*>/<VirtualHost *:$PUERTO_ELEGIDO>/g" /etc/apache2/sites-available/000-default.conf

    # Evitar warning AH00558
    if [[ ! -f /etc/apache2/conf-available/servername.conf ]]; then
        echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf
        a2enconf servername &>/dev/null
    fi

    if [[ -f /etc/apache2/conf-available/security.conf ]]; then
        sed -i "s/^ServerTokens .*/ServerTokens Prod/" /etc/apache2/conf-available/security.conf
        sed -i "s/^ServerSignature .*/ServerSignature Off/" /etc/apache2/conf-available/security.conf
        a2enconf security &>/dev/null
    fi

    cat > /etc/apache2/conf-available/security-headers.conf <<'EOF'
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
EOF
    a2enmod headers &>/dev/null
    a2enconf security-headers &>/dev/null

    configurar_firewall "$PUERTO_ELEGIDO"

    log_info "Validando configuración de Apache..."
    # Redirigir stderr a stdout para que configtest pueda leerse
    if ! apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
        log_warn "Error detectado en la configuración:"
        apache2ctl configtest
        log_error "La configuración de Apache tiene errores. Abortando reinicio."
    fi

    systemctl restart apache2
    sleep 2

    VERSION_REAL=$(apache2 -v 2>/dev/null | grep "Server version" | awk '{print $3}')
    crear_index "/var/www/html/index.html" "Apache2" "$VERSION_REAL" "$PUERTO_ELEGIDO"
    verificar_servicio "apache2" "$PUERTO_ELEGIDO"
}

instalar_nginx() {
    echo -e "\n\e[1m═══════════════════════════════════════\e[0m"
    echo -e "\e[1m  Instalando Nginx\e[0m"
    echo -e "\e[1m═══════════════════════════════════════\e[0m"

    obtener_versiones_nginx || return 1
    if [[ -z "$PUERTO_ELEGIDO" ]]; then pedir_puerto; fi

    log_info "Instalando Nginx versión $VERSION_ELEGIDA..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx 2>/dev/null
    if [[ $? -ne 0 ]]; then
        log_error "Falló la instalación de Nginx."
    fi

    log_info "Configurando puerto $PUERTO_ELEGIDO en Nginx..."
    local nginx_default="/etc/nginx/sites-available/default"
    if [[ -f "$nginx_default" ]]; then
        sed -i "s/listen [0-9]* default_server/listen $PUERTO_ELEGIDO default_server/g" "$nginx_default"
        sed -i "s/listen \[::\]:[0-9]* default_server/listen [::]:$PUERTO_ELEGIDO default_server/g" "$nginx_default"
    fi
    sed -i "s/listen[[:space:]]*[0-9]*;/listen $PUERTO_ELEGIDO;/g" /etc/nginx/nginx.conf 2>/dev/null

    if ! grep -q "server_tokens off" /etc/nginx/nginx.conf; then
        sed -i "/http {/a\\    server_tokens off;" /etc/nginx/nginx.conf
    fi

    cat > /etc/nginx/conf.d/security.conf <<'EOF'
map $request_method $block_method {
    default 0; TRACE 1; TRACK 1; DELETE 1; OPTIONS 1;
}
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
EOF

    configurar_firewall "$PUERTO_ELEGIDO"

    log_info "Validando configuración de Nginx..."
    if ! nginx -t 2>/dev/null; then
        log_error "La configuración de Nginx tiene errores. Abortando reinicio."
    fi

    systemctl restart nginx
    sleep 2

    VERSION_REAL=$(nginx -v 2>&1 | awk -F'/' '{print $2}')
    local webroot="/var/www/html"
    if [[ -d /usr/share/nginx/html ]]; then webroot="/usr/share/nginx/html"; fi
    crear_index "$webroot/index.html" "Nginx" "$VERSION_REAL" "$PUERTO_ELEGIDO"
    verificar_servicio "nginx" "$PUERTO_ELEGIDO"
}

instalar_tomcat() {
    echo -e "\n\e[1m═══════════════════════════════════════\e[0m"
    echo -e "\e[1m  Instalando Tomcat\e[0m"
    echo -e "\e[1m═══════════════════════════════════════\e[0m"

    obtener_versiones_tomcat || return 1
    if [[ -z "$PUERTO_ELEGIDO" ]]; then pedir_puerto; fi

    local TOMCAT_USER="tomcat"
    local TOMCAT_DIR="/opt/tomcat"
    local TOMCAT_VERSION="$VERSION_ELEGIDA"
    local TOMCAT_RAMA_NUM="$TOMCAT_RAMA"
    local TOMCAT_URL="https://dlcdn.apache.org/tomcat/tomcat-${TOMCAT_RAMA_NUM}/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"

    if ! id "$TOMCAT_USER" &>/dev/null; then
        log_info "Creando usuario dedicado '$TOMCAT_USER'..."
        useradd -r -m -U -d "$TOMCAT_DIR" -s /bin/false "$TOMCAT_USER"
    fi

    log_info "Descargando Tomcat $TOMCAT_VERSION..."
    local TMP_FILE="/tmp/tomcat-${TOMCAT_VERSION}.tar.gz"

    wget -q --show-progress "$TOMCAT_URL" -O "$TMP_FILE" 2>/dev/null
    if [[ $? -ne 0 || ! -s "$TMP_FILE" ]]; then
        log_error "Falló la descarga de Tomcat desde $TOMCAT_URL"
    fi

    mkdir -p "$TOMCAT_DIR"
    tar -xzf "$TMP_FILE" -C "$TOMCAT_DIR" --strip-components=1
    rm -f "$TMP_FILE"

    chown -R "$TOMCAT_USER":"$TOMCAT_USER" "$TOMCAT_DIR"
    chmod -R 750 "$TOMCAT_DIR"
    chmod -R 755 "$TOMCAT_DIR/webapps"

    log_info "Configurando puerto $PUERTO_ELEGIDO en Tomcat server.xml..."
    sed -i "s/port=\"8080\"/port=\"$PUERTO_ELEGIDO\"/g" "$TOMCAT_DIR/conf/server.xml"

    JAVA_HOME_PATH=$(dirname $(dirname $(readlink -f $(which java))))
    cat > /etc/systemd/system/tomcat.service <<EOF
[Unit]
Description=Apache Tomcat $TOMCAT_VERSION
After=network.target

[Service]
Type=forking
User=$TOMCAT_USER
Group=$TOMCAT_USER
Environment="JAVA_HOME=$JAVA_HOME_PATH"
Environment="CATALINA_HOME=$TOMCAT_DIR"
Environment="CATALINA_BASE=$TOMCAT_DIR"
Environment="CATALINA_PID=$TOMCAT_DIR/temp/tomcat.pid"
ExecStart=$TOMCAT_DIR/bin/startup.sh
ExecStop=$TOMCAT_DIR/bin/shutdown.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable tomcat &>/dev/null

    configurar_firewall "$PUERTO_ELEGIDO"
    systemctl start tomcat
    log_info "Esperando que Tomcat inicie (15s)..."
    sleep 15

    crear_index "$TOMCAT_DIR/webapps/ROOT/index.html" "Tomcat" "$TOMCAT_VERSION" "$PUERTO_ELEGIDO"
    chown "$TOMCAT_USER":"$TOMCAT_USER" "$TOMCAT_DIR/webapps/ROOT/index.html"
    verificar_servicio "tomcat" "$PUERTO_ELEGIDO"
}

# ==============================================================================
# OTRAS FUNCIONES (FIREWALL, INDEX, VERIFICAR, MOSTRAR_ESTADO)
# ==============================================================================
configurar_firewall() {
    local puerto=$1
    if command -v ufw &>/dev/null; then
        local ufw_status=$(ufw status | head -1)
        if echo "$ufw_status" | grep -q "active"; then
            log_info "Configurando UFW para puerto $puerto..."
            ufw allow "$puerto/tcp" comment "HTTP-Custom-$puerto" &>/dev/null
            log_success "Regla UFW agregada para puerto $puerto/tcp."
        else
            log_warn "UFW está inactivo. No se modificó el firewall."
        fi
    else
        log_warn "UFW no está instalado. Usando iptables directamente..."
        iptables -A INPUT -p tcp --dport "$puerto" -j ACCEPT 2>/dev/null && \
            log_success "Regla iptables agregada para puerto $puerto."
    fi
}

crear_index() {
    local ruta=$1
    local servicio=$2
    local version=$3
    local puerto=$4
    local fecha=$(date '+%Y-%m-%d %H:%M:%S')

    log_info "Creando página index.html personalizada..."
    cat > "$ruta" <<EOF
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$servicio - Práctica 6</title>
</head>
<body>
    <h1>🚀 Práctica 6 - $servicio</h1>
    <p>Version: $version</p>
    <p>Puerto: $puerto</p>
    <p>Desplegado: $fecha</p>
</body>
</html>
EOF
    log_success "index.html creado en $ruta"
}

verificar_servicio() {
    local servicio=$1
    local puerto=$2

    log_info "Verificando servicio $servicio en puerto $puerto..."
    if systemctl is-active --quiet "$servicio" 2>/dev/null; then
        log_success "Servicio $servicio está ACTIVO."
    else
        log_warn "El servicio $servicio no parece estar corriendo."
    fi

    if ss -tlnp 2>/dev/null | grep -q ":${puerto} "; then
        log_success "Puerto $puerto está escuchando."
    else
        log_warn "Puerto $puerto no detectado aún. Puede tardar unos segundos."
    fi

    log_info "Probando respuesta HTTP..."
    sleep 2
    local http_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://localhost:$puerto" 2>/dev/null)
    if [[ "$http_response" == "200" ]]; then
        log_success "Servidor responde HTTP 200 en puerto $puerto ✓"
    else
        log_warn "Respuesta HTTP: $http_response (puede estar iniciando aún)"
    fi
}

mostrar_estado_servicios() {
    echo -e "\n\e[1mEstado de servicios HTTP:\e[0m"
    echo -e "──────────────────────────────────────────"
    for svc in apache2 nginx tomcat; do
        if systemctl list-units --type=service 2>/dev/null | grep -q "$svc"; then
            local estado=$(systemctl is-active "$svc" 2>/dev/null)
            local puerto_activo=$(ss -tlnp 2>/dev/null | grep "$svc" | awk '{print $4}' | awk -F':' '{print $NF}' | head -1)
            echo -e "  \e[1m$svc\e[0m: $estado \e[0;36m(puerto: ${puerto_activo:-desconocido})\e[0m"
        else
            echo -e "  \e[1m$svc\e[0m: \e[1;33mno instalado\e[0m"
        fi
    done
    echo ""
}

purgar_servicios() {
    log_info "Iniciando proceso de purgado total de servicios HTTP..."
    echo -e "\n\e[1;31mADVERTENCIA: Esto eliminará apache2, nginx y tomcat, junto con sus configuraciones.\e[0m"
    if [[ "$INTERACTIVO" -eq 1 ]]; then
        read -p "¿Estás seguro de que deseas continuar? [s/N]: " confirmacion
        if [[ "$confirmacion" != "s" && "$confirmacion" != "S" ]]; then
            log_info "Purgado cancelado por el usuario."
            return 0
        fi
    fi

    # Purgar Apache2
    log_info "Eliminando Apache2..."
    systemctl stop apache2 2>/dev/null
    apt-get purge -y apache2 apache2-utils apache2-bin apache2.2-common 2>/dev/null
    apt-get autoremove -y 2>/dev/null
    rm -rf /etc/apache2 /var/www/html/* /var/log/apache2

    # Purgar Nginx
    log_info "Eliminando Nginx..."
    systemctl stop nginx 2>/dev/null
    apt-get purge -y nginx nginx-common nginx-full 2>/dev/null
    apt-get autoremove -y 2>/dev/null
    rm -rf /etc/nginx /usr/share/nginx/html/* /var/log/nginx

    # Purgar Tomcat
    log_info "Eliminando Tomcat..."
    systemctl stop tomcat 2>/dev/null
    systemctl disable tomcat 2>/dev/null
    rm -f /etc/systemd/system/tomcat.service
    systemctl daemon-reload
    rm -rf /opt/tomcat
    userdel -r tomcat 2>/dev/null || true

    log_success "Purgado completado. Todos los servicios HTTP predeterminados han sido eliminados."
}

mostrar_ayuda() {
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help               Muestra este mensaje de ayuda"
    echo "  --status                 Muestra el estado de los servicios HTTP"
    echo "  --purge                  Elimina todas las configuraciones y servicios HTTP (apache, nginx, tomcat)"
    echo "  -s, --service <servicio> Servicio a instalar (apache2, nginx, tomcat)"
    echo "  -p, --port <puerto>      Puerto personalizado para la instalación"
    echo ""
    echo "Ejemplo: sudo $0 --service nginx --port 8080"
}

# ==============================================================================
# MENÚ PRINCIPAL E INICIO
# ==============================================================================
mostrar_menu() {
    clear
    echo -e "\e[1;36m  Práctica 6 - Despliegue HTTP Multi-Versión \e[0m"
    echo -e "  \e[1m1)\e[0m Instalar Apache2"
    echo -e "  \e[1m2)\e[0m Instalar Nginx"
    echo -e "  \e[1m3)\e[0m Instalar Tomcat"
    echo -e "  \e[1m4)\e[0m Verificar servicios instalados"
    echo -e "  \e[1m5)\e[0m Purgar todo (Eliminar servicios)"
    echo -e "  \e[1m0)\e[0m Salir"
    echo -e "\e[0;36m  Selecciona una opción:\e[0m "
}

PUERTO_ELEGIDO=""
SERVICIO_ELEGIDO=""
INTERACTIVO=1

# Parámetros de comando
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help)
            mostrar_ayuda
            exit 0
            ;;
        --status)
            mostrar_estado_servicios
            exit 0
            ;;
        --purge)
            INTERACTIVO=0
            purgar_servicios
            exit 0
            ;;
        -s|--service)
            SERVICIO_ELEGIDO="$2"
            INTERACTIVO=0
            shift
            ;;
        -p|--port)
            PUERTO_ELEGIDO="$2"
            shift
            ;;
        *)
            log_error "Parámetro desconocido: $1. Usa --help para ver las opciones."
            ;;
    esac
    shift
done

verificar_conectividad

# Flujo No Interactivo
if [[ "$INTERACTIVO" -eq 0 ]]; then
    if [[ -z "$PUERTO_ELEGIDO" ]]; then
        log_error "Debes especificar un puerto con -p o --port en modo no interactivo."
    fi

    if ! validar_puerto_ext "$PUERTO_ELEGIDO" 2>/dev/null; then
        exit 1
    fi

    case "$SERVICIO_ELEGIDO" in
        apache2) instalar_apache ;;
        nginx) instalar_nginx ;;
        tomcat) instalar_tomcat ;;
        *) log_error "El servicio $SERVICIO_ELEGIDO no es soportado. Usa apache2, nginx o tomcat." ;;
    esac
    exit 0
fi

# Flujo Interactivo
while true; do
    mostrar_menu
    read -r opcion
    opcion=$(echo "$opcion" | tr -cd '0-9')

    case "$opcion" in
        1) PUERTO_ELEGIDO=""; instalar_apache ;;
        2) PUERTO_ELEGIDO=""; instalar_nginx ;;
        3) PUERTO_ELEGIDO=""; instalar_tomcat ;;
        4) mostrar_estado_servicios ;;
        5) purgar_servicios ;;
        0) log_success "Saliendo..."; exit 0 ;;
        *) log_warn "Opción inválida. Ingresa 0, 1, 2, 3, 4 o 5."; sleep 1 ;;
    esac

    echo -e "\n\e[0;36mPresiona ENTER para volver al menú...\e[0m"
    read -r
done

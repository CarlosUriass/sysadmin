#!/bin/bash
# ==============================================================================
# Script: deploy_containers.sh
# Descripcion: Orquestador para la migracion de servicios esenciales a
#              contenedores Docker personalizados (Nginx + PostgreSQL + FTP)
#              con enfoque en seguridad y almacenamiento.
#
# Uso: sudo bash deploy_containers.sh [--deploy|--purge|--status|--test|-h]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ==============================================================================
# 0. CARGA DE UTILIDADES
# ==============================================================================
if [[ -f "$SCRIPT_DIR/../../utils/logs/logger.sh" ]]; then
    source "$SCRIPT_DIR/../../utils/logs/logger.sh"
else
    echo "ERROR: No se encuentra utils/logs/logger.sh"
    exit 1
fi

# ==============================================================================
# 1. CONSTANTES DE CONFIGURACION
# ==============================================================================
# Red
NETWORK_NAME="infra_red"
NETWORK_SUBNET="172.20.0.0/16"
NETWORK_GATEWAY="172.20.0.1"

# IPs fijas
WEB_IP="172.20.0.10"
DB_IP="172.20.0.20"
FTP_IP="172.20.0.30"

# Nombres de contenedores
WEB_CONTAINER="web_server"
DB_CONTAINER="db_server"
FTP_CONTAINER="ftp_server"

# Nombres de imagenes personalizadas
WEB_IMAGE="infra/nginx-hardened"
DB_IMAGE="infra/postgres-backup"

# Volumenes
VOL_DB="db_data"
VOL_WEB="web_content"

# Limites de recursos
WEB_MEM="512m"
WEB_CPU="0.5"
DB_MEM="512m"
DB_CPU="0.5"
FTP_MEM="256m"
FTP_CPU="0.25"

# PostgreSQL
PG_DB="infraestructura"
PG_USER="admin"
PG_PASS="SecureP@ss2026"

# FTP
FTP_USER="ftpuser"
FTP_PASS="FtpSecure2026"

# Directorio de respaldos en el host
BACKUP_HOST_DIR="/opt/backups/postgres"

# Directorio compartido FTP -> Web (uploads)
FTP_UPLOAD_DIR="/opt/docker/ftp_uploads"

# ==============================================================================
# 2. FUNCIONES DE VERIFICACION
# ==============================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log_error "Este script requiere privilegios de root (sudo)."
    fi
}

verificar_docker() {
    log_info "Verificando instalacion de Docker..."

    if command -v docker &>/dev/null; then
        local docker_ver
        docker_ver=$(docker --version | awk '{print $3}' | tr -d ',')
        log_success "Docker ya instalado: v$docker_ver"
    else
        log_info "Docker no encontrado. Instalando..."

        if [[ -f "$SCRIPT_DIR/../../utils/sh/install_package.sh" ]]; then
            bash "$SCRIPT_DIR/../../utils/sh/install_package.sh" -p docker.io
        else
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq docker.io || log_error "No se pudo instalar Docker"
        fi

        systemctl enable docker 2>/dev/null || true
        systemctl start docker || log_error "No se pudo iniciar Docker"
        log_success "Docker instalado e iniciado."
    fi

    # Verificar que el daemon este corriendo
    if ! docker info &>/dev/null; then
        systemctl start docker || log_error "El daemon de Docker no responde."
    fi
}

verificar_puertos() {
    log_info "Verificando disponibilidad de puertos..."

    local CHECK_PORT="$SCRIPT_DIR/../../utils/sh/check_port_in_use.sh"

    for port in 80 5432 21; do
        if [[ -f "$CHECK_PORT" ]]; then
            # check_port_in_use.sh retorna 0 si esta en uso
            if bash "$CHECK_PORT" --port "$port" 2>/dev/null; then
                log_warn "Puerto $port esta en uso. Puede haber conflicto."
            fi
        else
            if lsof -Pi :"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
                log_warn "Puerto $port esta en uso. Puede haber conflicto."
            fi
        fi
    done
}

# ==============================================================================
# 3. CREACION DE RED PERSONALIZADA
# ==============================================================================

crear_red() {
    log_info "Configurando red bridge personalizada '$NETWORK_NAME'..."

    # Validar formato de subnet usando utilidad si existe
    local VALIDATE_IP="$SCRIPT_DIR/../../utils/sh/validate_ip.sh"
    if [[ -f "$VALIDATE_IP" ]]; then
        local subnet_ip="${NETWORK_SUBNET%%/*}"
        if ! bash "$VALIDATE_IP" --ip "$subnet_ip" 2>/dev/null; then
            log_error "Formato de subnet invalido: $NETWORK_SUBNET"
        fi
    fi

    if docker network inspect "$NETWORK_NAME" &>/dev/null; then
        log_success "Red '$NETWORK_NAME' ya existe."
    else
        docker network create \
            --driver bridge \
            --subnet "$NETWORK_SUBNET" \
            --gateway "$NETWORK_GATEWAY" \
            "$NETWORK_NAME" || log_error "No se pudo crear la red '$NETWORK_NAME'"

        log_success "Red '$NETWORK_NAME' creada (subnet: $NETWORK_SUBNET)."
    fi
}

# ==============================================================================
# 4. CREACION DE VOLUMENES PERSISTENTES
# ==============================================================================

crear_volumenes() {
    log_info "Creando volumenes persistentes..."

    for vol in "$VOL_DB" "$VOL_WEB"; do
        if docker volume inspect "$vol" &>/dev/null; then
            log_success "Volumen '$vol' ya existe."
        else
            docker volume create "$vol" || log_error "No se pudo crear volumen '$vol'"
            log_success "Volumen '$vol' creado."
        fi
    done

    # Crear directorios del host para respaldos y FTP
    mkdir -p "$BACKUP_HOST_DIR"
    mkdir -p "$FTP_UPLOAD_DIR"
    log_info "Directorios del host creados: $BACKUP_HOST_DIR, $FTP_UPLOAD_DIR"
}

# ==============================================================================
# 5. CONSTRUCCION DE IMAGENES PERSONALIZADAS
# ==============================================================================

construir_imagenes() {
    log_info "Construyendo imagenes Docker personalizadas..."

    # --- Preparar contexto de build para Nginx ---
    local web_build_ctx="$SCRIPT_DIR/dockerfiles/web/build_context"
    mkdir -p "$web_build_ctx/config"
    mkdir -p "$web_build_ctx/web_content"

    cp "$SCRIPT_DIR/dockerfiles/web/Dockerfile"      "$web_build_ctx/Dockerfile"
    cp "$SCRIPT_DIR/config/nginx/nginx.conf"          "$web_build_ctx/config/nginx.conf"
    cp "$SCRIPT_DIR/config/nginx/default.conf"        "$web_build_ctx/config/default.conf"
    cp -r "$SCRIPT_DIR/web_content/"*                 "$web_build_ctx/web_content/" 2>/dev/null || true

    log_info "Construyendo imagen del servidor web ($WEB_IMAGE)..."
    docker build -t "$WEB_IMAGE" "$web_build_ctx" || log_error "Fallo al construir imagen web"
    log_success "Imagen '$WEB_IMAGE' construida."

    # Limpiar contexto temporal
    rm -rf "$web_build_ctx"

    # --- Preparar contexto de build para PostgreSQL ---
    local db_build_ctx="$SCRIPT_DIR/dockerfiles/db/build_context"
    mkdir -p "$db_build_ctx/config"

    cp "$SCRIPT_DIR/dockerfiles/db/Dockerfile"           "$db_build_ctx/Dockerfile"
    cp "$SCRIPT_DIR/config/postgres/init.sql"            "$db_build_ctx/config/init.sql"
    cp "$SCRIPT_DIR/config/postgres/backup.sh"           "$db_build_ctx/config/backup.sh"

    log_info "Construyendo imagen de base de datos ($DB_IMAGE)..."
    docker build -t "$DB_IMAGE" "$db_build_ctx" || log_error "Fallo al construir imagen db"
    log_success "Imagen '$DB_IMAGE' construida."

    # Limpiar contexto temporal
    rm -rf "$db_build_ctx"
}

# ==============================================================================
# 6. DESPLIEGUE DE CONTENEDORES
# ==============================================================================

desplegar_web() {
    log_info "Desplegando contenedor del servidor web ($WEB_CONTAINER)..."

    if docker ps -a --format '{{.Names}}' | grep -q "^${WEB_CONTAINER}$"; then
        log_warn "Contenedor '$WEB_CONTAINER' ya existe. Recreando..."
        docker rm -f "$WEB_CONTAINER" &>/dev/null || true
    fi

    docker run -d \
        --name "$WEB_CONTAINER" \
        --network "$NETWORK_NAME" \
        --ip "$WEB_IP" \
        -p 80:80 \
        --memory="$WEB_MEM" \
        --cpus="$WEB_CPU" \
        --restart unless-stopped \
        -v "$VOL_WEB":/usr/share/nginx/html \
        -v "$FTP_UPLOAD_DIR":/usr/share/nginx/html/uploads:ro \
        "$WEB_IMAGE" || log_error "No se pudo desplegar el contenedor web"

    # Copiar contenido web al volumen (solo la primera vez si esta vacio)
    if ! docker exec "$WEB_CONTAINER" test -f /usr/share/nginx/html/index.html 2>/dev/null; then
        log_info "Copiando contenido web al volumen..."
        docker cp "$SCRIPT_DIR/web_content/." "$WEB_CONTAINER":/usr/share/nginx/html/
    fi

    log_success "Contenedor '$WEB_CONTAINER' desplegado (IP: $WEB_IP, Puerto: 80, RAM: $WEB_MEM, CPU: $WEB_CPU)."
}

desplegar_db() {
    log_info "Desplegando contenedor de base de datos ($DB_CONTAINER)..."

    if docker ps -a --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
        log_warn "Contenedor '$DB_CONTAINER' ya existe. Recreando..."
        docker rm -f "$DB_CONTAINER" &>/dev/null || true
    fi

    docker run -d \
        --name "$DB_CONTAINER" \
        --network "$NETWORK_NAME" \
        --ip "$DB_IP" \
        -p 5432:5432 \
        --memory="$DB_MEM" \
        --cpus="$DB_CPU" \
        --restart unless-stopped \
        -e POSTGRES_DB="$PG_DB" \
        -e POSTGRES_USER="$PG_USER" \
        -e POSTGRES_PASSWORD="$PG_PASS" \
        -v "$VOL_DB":/var/lib/postgresql/data \
        -v "$BACKUP_HOST_DIR":/backups \
        "$DB_IMAGE" || log_error "No se pudo desplegar el contenedor de BD"

    log_success "Contenedor '$DB_CONTAINER' desplegado (IP: $DB_IP, Puerto: 5432, RAM: $DB_MEM, CPU: $DB_CPU)."

    # Esperar a que PostgreSQL este listo
    log_info "Esperando a que PostgreSQL este listo..."
    local retries=0
    while ! docker exec "$DB_CONTAINER" pg_isready -U "$PG_USER" &>/dev/null; do
        retries=$((retries + 1))
        if (( retries > 30 )); then
            log_error "PostgreSQL no respondio en tiempo limite (30s)."
        fi
        sleep 1
    done
    log_success "PostgreSQL listo y aceptando conexiones."
}

desplegar_ftp() {
    log_info "Desplegando contenedor FTP ($FTP_CONTAINER)..."

    if docker ps -a --format '{{.Names}}' | grep -q "^${FTP_CONTAINER}$"; then
        log_warn "Contenedor '$FTP_CONTAINER' ya existe. Recreando..."
        docker rm -f "$FTP_CONTAINER" &>/dev/null || true
    fi

    docker run -d \
        --name "$FTP_CONTAINER" \
        --network "$NETWORK_NAME" \
        --ip "$FTP_IP" \
        -p 21:21 \
        -p 21100-21110:21100-21110 \
        --memory="$FTP_MEM" \
        --cpus="$FTP_CPU" \
        --restart unless-stopped \
        -e FTP_USER="$FTP_USER" \
        -e FTP_PASS="$FTP_PASS" \
        -e PASV_ADDRESS="0.0.0.0" \
        -e PASV_MIN_PORT=21100 \
        -e PASV_MAX_PORT=21110 \
        -v "$FTP_UPLOAD_DIR":/home/vsftpd/"$FTP_USER" \
        fauria/vsftpd || log_error "No se pudo desplegar el contenedor FTP"

    log_success "Contenedor '$FTP_CONTAINER' desplegado (IP: $FTP_IP, Puerto: 21, RAM: $FTP_MEM, CPU: $FTP_CPU)."
}

# ==============================================================================
# 7. ESTADO DE LOS SERVICIOS
# ==============================================================================

mostrar_estado() {
    echo ""
    echo "======================================================================"
    echo "  ESTADO DE LA INFRAESTRUCTURA DOCKER"
    echo "======================================================================"
    echo ""

    log_info "Contenedores:"
    docker ps -a --filter "network=$NETWORK_NAME" \
        --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}" 2>/dev/null || \
        docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}"
    echo ""

    log_info "Uso de recursos (docker stats):"
    docker stats --no-stream --format \
        "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}" \
        "$WEB_CONTAINER" "$DB_CONTAINER" "$FTP_CONTAINER" 2>/dev/null || true
    echo ""

    log_info "Volumenes:"
    docker volume ls --filter "name=$VOL_DB" --filter "name=$VOL_WEB" 2>/dev/null || true
    echo ""

    log_info "Red '$NETWORK_NAME':"
    docker network inspect "$NETWORK_NAME" --format \
        '{{range .Containers}}  - {{.Name}} ({{.IPv4Address}}){{"\n"}}{{end}}' 2>/dev/null || \
        log_warn "Red '$NETWORK_NAME' no encontrada."
    echo ""
}

# ==============================================================================
# 8. PURGADO COMPLETO
# ==============================================================================

purgar() {
    log_warn "Iniciando purgado completo de la infraestructura Docker..."

    # Detener y eliminar contenedores
    for ctr in "$WEB_CONTAINER" "$DB_CONTAINER" "$FTP_CONTAINER"; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${ctr}$"; then
            docker rm -f "$ctr" &>/dev/null
            log_info "Contenedor '$ctr' eliminado."
        fi
    done

    # Eliminar imagenes personalizadas
    for img in "$WEB_IMAGE" "$DB_IMAGE"; do
        if docker images -q "$img" 2>/dev/null | grep -q .; then
            docker rmi -f "$img" &>/dev/null || true
            log_info "Imagen '$img' eliminada."
        fi
    done

    # Eliminar volumenes
    for vol in "$VOL_DB" "$VOL_WEB"; do
        if docker volume inspect "$vol" &>/dev/null; then
            docker volume rm "$vol" &>/dev/null || true
            log_info "Volumen '$vol' eliminado."
        fi
    done

    # Eliminar red
    if docker network inspect "$NETWORK_NAME" &>/dev/null; then
        docker network rm "$NETWORK_NAME" &>/dev/null || true
        log_info "Red '$NETWORK_NAME' eliminada."
    fi

    log_success "Purgado completado. Infraestructura Docker limpia."
}

# ==============================================================================
# 9. EJECUTAR PRUEBAS
# ==============================================================================

ejecutar_pruebas() {
    local test_script="$SCRIPT_DIR/tests/run_tests.sh"
    if [[ -f "$test_script" ]]; then
        bash "$test_script"
    else
        log_error "Script de pruebas no encontrado: $test_script"
    fi
}

# ==============================================================================
# 10. DESPLIEGUE COMPLETO
# ==============================================================================

desplegar() {
    log_info "=== INICIO DEL DESPLIEGUE DE INFRAESTRUCTURA ==="
    echo ""

    verificar_docker
    verificar_puertos
    crear_red
    crear_volumenes
    construir_imagenes
    desplegar_web
    desplegar_db
    desplegar_ftp

    echo ""
    log_success "=== DESPLIEGUE COMPLETADO EXITOSAMENTE ==="
    echo ""
    mostrar_estado
}

# ==============================================================================
# MAIN
# ==============================================================================

mostrar_ayuda() {
    echo "======================================================================"
    echo "  Migracion de Servicios a Contenedores Docker"
    echo "======================================================================"
    echo ""
    echo "Uso: sudo bash $0 [OPCION]"
    echo ""
    echo "Opciones:"
    echo "  --deploy     Despliegue completo (red + volumenes + imagenes + contenedores)"
    echo "  --purge      Eliminar toda la infraestructura (contenedores, imagenes, volumenes, red)"
    echo "  --status     Mostrar estado de los servicios desplegados"
    echo "  --test       Ejecutar protocolo de pruebas (10.1 - 10.4)"
    echo "  --backup     Ejecutar respaldo manual de PostgreSQL"
    echo "  -h, --help   Mostrar esta ayuda"
    echo ""
    echo "Servicios desplegados:"
    echo "  - Nginx (Alpine)       -> Puerto 80   | 172.20.0.10 | 512MB RAM"
    echo "  - PostgreSQL 16        -> Puerto 5432  | 172.20.0.20 | 512MB RAM"
    echo "  - vsftpd (FTP)         -> Puerto 21    | 172.20.0.30 | 256MB RAM"
    echo ""
    echo "Red: infra_red (172.20.0.0/16)"
    echo "Volumenes: db_data, web_content"
    echo ""
}

main() {
    if [[ $# -eq 0 ]]; then
        mostrar_ayuda
        exit 0
    fi

    case "$1" in
        --deploy)
            check_root
            desplegar
            ;;
        --purge)
            check_root
            purgar
            ;;
        --status)
            mostrar_estado
            ;;
        --test)
            check_root
            ejecutar_pruebas
            ;;
        --backup)
            check_root
            log_info "Ejecutando respaldo manual de PostgreSQL..."
            docker exec "$DB_CONTAINER" /usr/local/bin/backup.sh || \
                log_error "Error al ejecutar respaldo"
            log_success "Respaldo manual completado. Archivos en $BACKUP_HOST_DIR"
            ;;
        -h|--help)
            mostrar_ayuda
            ;;
        *)
            log_warn "Opcion desconocida: $1"
            mostrar_ayuda
            exit 1
            ;;
    esac
}

main "$@"

#!/bin/bash
# ==============================================================================
# Script: ftp.sh
# Descripcion: Instalación y configuración automatizada, segura e idempotente 
#              de un servidor FTP (vsftpd) en Linux Ubuntu.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="/var/log/ftp-automation.log"

# ==============================================================================
# 0. FUNCIONES DE UTILIDAD Y LOGGING
# ==============================================================================
log_info() { echo -e "[\e[34mINFO\e[0m] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "[\e[32mOK\e[0m]   $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "[\e[33mWARN\e[0m] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "[\e[31mFAIL\e[0m] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Este script debe ejecutarse como root (con sudo)."
        exit 1
    fi
    touch "$LOG_FILE" || { echo "No se pudo crear el archivo de log $LOG_FILE"; exit 1; }
}

instalar_paquetes() {
    log_info "Verificando e instalando paquetes necesarios..."
    # Intenta usar la utilidad si existe, sino usa apt-get directamente
    if [[ -f "$SCRIPT_DIR/../../utils/sh/install_package.sh" ]]; then
        bash "$SCRIPT_DIR/../../utils/sh/install_package.sh" -p vsftpd ufw fail2ban openssl
    else
        export DEBIAN_FRONTEND=noninteractive
        for pkg in vsftpd ufw fail2ban openssl; do
            if dpkg -s "$pkg" &>/dev/null; then
                log_success "$pkg ya se encuentra instalado."
            else
                log_info "Instalando $pkg..."
                apt-get update -qq >/dev/null && apt-get install -y -qq "$pkg" >/dev/null || log_error "Fallo instalando $pkg"
                log_success "$pkg instalado exitosamente."
            fi
        done
    fi
}

# ==============================================================================
# 1. GESTION DE DIRECTORIOS BASE Y GRUPOS
# ==============================================================================
configurar_base() {
    log_info "Configurando directorios base y grupos..."
    
    # Crear grupos si no existen
    for grupo in ftpusers reprobados recursadores; do
        if getent group "$grupo" >/dev/null; then
            log_success "El grupo $grupo ya existe."
        else
            groupadd "$grupo"
            log_success "Grupo $grupo creado."
        fi
    done

    # Crear directorios con idempotencia
    mkdir -p /srv/ftp/general
    mkdir -p /srv/ftp/reprobados
    mkdir -p /srv/ftp/recursadores

    # Permisos Exactos:
    # General: Owner root, Group ftpusers, Perms 775 (lectura global, escritura grupo autenticado, anónimo r-x)
    chown root:ftpusers /srv/ftp/general
    chmod 775 /srv/ftp/general
    
    # Reprobados: Owner root, Group reprobados, Perms 770 (solo grupo)
    chown root:reprobados /srv/ftp/reprobados
    chmod 770 /srv/ftp/reprobados
    
    # Recursadores: Owner root, Group recursadores, Perms 770 (solo grupo)
    chown root:recursadores /srv/ftp/recursadores
    chmod 770 /srv/ftp/recursadores

    log_success "Directorios base configurados con permisos seguros."
}

# ==============================================================================
# 2. CONFIGURACION VSFTPD
# ==============================================================================
configurar_vsftpd() {
    log_info "Configurando vsftpd..."
    local VS_CONF="/etc/vsftpd.conf"
    
    # Backup idempotente
    if [[ ! -f "${VS_CONF}.bak" ]]; then
        cp "$VS_CONF" "${VS_CONF}.bak"
        log_success "Backup creado: ${VS_CONF}.bak"
    fi

    # Generar Certificado SSL si no existe
    if [[ ! -f /etc/ssl/private/vsftpd.pem ]]; then
        log_info "Generando certificado autofirmado para FTPS..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/vsftpd.pem \
            -out /etc/ssl/private/vsftpd.pem \
            -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=Academico/CN=ftp.local" 2>/dev/null
        chmod 600 /etc/ssl/private/vsftpd.pem
        log_success "Certificado SSL generado."
    fi

    # Escribir configuración (sobrescribe para asegurar estado deseado - idempotente)
    cat <<EOF > "$VS_CONF"
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd

# Accesos y Rutas
anon_root=/srv/ftp/general
user_sub_token=\$USER
local_root=/srv/ftp/usuarios/\$USER

# Logging
xferlog_file=/var/log/vsftpd.log
dual_log_enable=YES
vsftpd_log_file=/var/log/vsftpd.log

# Modo Pasivo
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100

# FTPS (Seguridad Opcional)
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=NO
force_local_logins_ssl=NO
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
EOF

    log_success "Configuración de vsftpd aplicada."
    
    # Reiniciar servicio
    systemctl restart vsftpd || log_error "Fallo al reiniciar vsftpd"
    systemctl enable vsftpd 2>/dev/null || true
    log_success "Servicio vsftpd reiniciado y habilitado."
}

# ==============================================================================
# 3. FIREWALL Y FAIL2BAN
# ==============================================================================
configurar_seguridad() {
    log_info "Configurando Firewall y Fail2Ban..."

    # Firewall
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        for port in 20/tcp 21/tcp 40000:40100/tcp 990/tcp; do
            if ! ufw status | grep -q "$port"; then
                ufw allow $port >/dev/null 2>&1 || true
            fi
        done
        log_success "Reglas de UFW aplicadas para FTP y Modo Pasivo."
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=20-21/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=40000-40100/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=990/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_success "Reglas de firewalld aplicadas."
    else
        log_warn "No se detectó un firewall activo (UFW o Firewalld)."
    fi

    # Fail2Ban
    local FAIL2BAN_CONF="/etc/fail2ban/jail.local"
    if ! grep -q "\[vsftpd\]" "$FAIL2BAN_CONF" 2>/dev/null; then
        cat <<EOF >> "$FAIL2BAN_CONF"
[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
logpath = /var/log/vsftpd.log
maxretry = 5
bantime = 3600
EOF
        systemctl restart fail2ban || true
        log_success "Fail2Ban configurado para vsftpd (maxretry=5, bantime=1h)."
    else
        log_success "Fail2Ban ya estaba configurado para vsftpd."
    fi
}

# ==============================================================================
# 4. GESTIÓN DE USUARIOS
# ==============================================================================
# Función para montar de forma segura y permanente (idempotente)
montar_directorio() {
    local src="$1"
    local dest="$2"
    
    if grep -q "$dest" /etc/fstab; then
        log_success "El montaje para $dest ya existe en fstab."
    else
        echo "$src $dest none bind 0 0" >> /etc/fstab
        log_info "Agregado $dest a fstab."
    fi

    if ! mountpoint -q "$dest"; then
        mount "$dest" || log_error "No se pudo montar $dest"
        log_success "Montado $src en $dest"
    fi
}

crear_usuario() {
    local username="$1"
    local grupo="$2"
    local password="$3"
    
    # Validar regex seguro para evitar ../ o nombres inválidos
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{2,31}$ ]]; then
        log_error "Nombre de usuario inválido. Use minúsculas, números, guiones."
    fi

    # Crear grupo complementario para vsftpd acceso a general
    # El usuario pertenece a su grupo primario (reprobados/recursadores)
    # y también al grupo 'ftpusers'.
    if id "$username" &>/dev/null; then
        log_warn "El usuario $username ya existe. Verificando estructura..."
    else
        useradd -m -d "/srv/ftp/usuarios/$username" -s /usr/sbin/nologin -g "$grupo" -G ftpusers "$username"
        echo "$username:$password" | chpasswd
        log_success "Usuario $username creado en el sistema."
    fi

    local u_home="/srv/ftp/usuarios/$username"
    
    # El home (chroot_root) debe pertenecer a root y no ser escribible por otros para seguridad
    chown root:root "$u_home"
    chmod 755 "$u_home"

    # Crear directorios de vista
    mkdir -p "$u_home/general"
    mkdir -p "$u_home/$grupo"
    mkdir -p "$u_home/$username"

    # Permisos de la carpeta personal (acceso exclusivo)
    chown "$username:$grupo" "$u_home/$username"
    chmod 700 "$u_home/$username"
    
    # Montar directorios compartidos
    montar_directorio "/srv/ftp/general" "$u_home/general"
    montar_directorio "/srv/ftp/$grupo" "$u_home/$grupo"

    log_success "Estructura y permisos configurados para $username."
}

# Función para dar de baja un grupo montado para un usuario
desmontar_directorio() {
    local dest="$1"
    if mountpoint -q "$dest"; then
        umount "$dest" || log_error "No se pudo desmontar $dest"
    fi
    # Eliminar linea de fstab de forma segura
    sed -i "\@ $dest none bind 0 0@d" /etc/fstab || true
    rmdir "$dest" 2>/dev/null || rm -rf "$dest"
    log_success "Directorio $dest desmontado y eliminado correctamente."
}

cambiar_grupo_usuario() {
    local username="$1"
    local nuevo_grupo="$2"

    if ! id "$username" &>/dev/null; then
        log_error "El usuario $username no existe."
    fi

    if [[ "$nuevo_grupo" != "reprobados" && "$nuevo_grupo" != "recursadores" ]]; then
        log_error "Grupo inválido. Debe ser 'reprobados' o 'recursadores'."
    fi

    local grupo_actual=$(id -gn "$username")
    if [[ "$grupo_actual" == "$nuevo_grupo" ]]; then
        log_success "El usuario $username ya pertenece a $nuevo_grupo. No hay cambios."
        return 0
    fi

    log_info "Cambiando usuario $username de $grupo_actual a $nuevo_grupo..."
    
    local u_home="/srv/ftp/usuarios/$username"

    # Desmontar viejo grupo
    desmontar_directorio "$u_home/$grupo_actual"

    # Cambiar grupo primario en sistema
    usermod -g "$nuevo_grupo" "$username"

    # Cambiar propiedad de la carpeta personal
    chown "$username:$nuevo_grupo" "$u_home/$username"

    # Crear y montar nuevo grupo
    mkdir -p "$u_home/$nuevo_grupo"
    montar_directorio "/srv/ftp/$nuevo_grupo" "$u_home/$nuevo_grupo"

    log_success "Cambio de grupo exitoso para $username."
}

# ==============================================================================
# 5. MENÚ INTERACTIVO
# ==============================================================================
menu_interactivo() {
    configurar_base
    configurar_vsftpd
    configurar_seguridad
    
    echo "======================================"
    echo "  Configuración Base FTP completada.  "
    echo "======================================"
    echo ""
    
    while true; do
        read -p "¿Cuántos usuarios desea crear? (0 para salir): " num_users
        if ! [[ "$num_users" =~ ^[0-9]+$ ]]; then
            echo "Por favor ingrese un número válido."
            continue
        fi

        if [[ "$num_users" -eq 0 ]]; then
            log_info "Finalizando script."
            break
        fi

        for (( i=1; i<=num_users; i++ )); do
            echo ""
            echo "--- Usuario $i ---"
            
            local u_name
            while true; do
                read -p "Nombre de usuario: " u_name
                if [[ "$u_name" =~ ^[a-z_][a-z0-9_-]{2,31}$ ]]; then
                    break
                else
                    echo "Nombre inválido. Use minúsculas, números y guiones (ej. juan_perez)."
                fi
            done

            local u_pass
            while true; do
                read -s -p "Contraseña: " u_pass
                echo ""
                if [[ -z "$u_pass" ]]; then
                    echo "La contraseña no puede estar vacía."
                else
                    break
                fi
            done

            local u_grupo
            while true; do
                read -p "Grupo (reprobados/recursadores): " u_grupo
                if [[ "$u_grupo" == "reprobados" || "$u_grupo" == "recursadores" ]]; then
                    break
                else
                    echo "Debe elegir 'reprobados' o 'recursadores'."
                fi
            done

            crear_usuario "$u_name" "$u_grupo" "$u_pass"
        done
        break
    done
}

# ==============================================================================
# 6. MANTENIMIENTO Y AYUDA
# ==============================================================================
mostrar_ayuda() {
    echo "Uso: sudo bash $0 [OPCION]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help                          Mostrar esta ayuda"
    echo "  -p, --purge                         Purgar vsftpd, borrar usuarios, configuraciones y directorios"
    echo "  -c, --change-group <user> <group>   Cambiar el grupo de un usuario (reprobados/recursadores)"
    echo "  Sin opciones                        Inicia el flujo de instalación y el menú interactivo"
}

purgar_ftp() {
    log_warn "Iniciando purgado completo de FTP. Esto borrará datos y configuraciones..."
    
    # 1. Detener servicio
    systemctl stop vsftpd 2>/dev/null || true
    systemctl disable vsftpd 2>/dev/null || true

    # 2. Desinstalar paquete
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y -qq vsftpd >/dev/null 2>&1 || true
    apt-get autoremove -y -qq >/dev/null 2>&1 || true

    # 3. Desmontar directorios en fstab
    log_info "Desmontando directorios chroot enlazados..."
    while read -r line; do
        if [[ "$line" == *"/srv/ftp/"* ]]; then
            dest=$(echo "$line" | awk '{print $2}')
            if mountpoint -q "$dest"; then
                umount "$dest" 2>/dev/null || true
            fi
        fi
    done < /etc/fstab
    # Borrar lineas de fstab
    sed -i '\@/srv/ftp/@d' /etc/fstab || true

    # 4. Eliminar usuarios (Todos los que pertenezcan a los grupos)
    log_info "Eliminando usuarios FTP y directorios..."
    for user in $(awk -F: '$4 >= 1000 {print $1}' /etc/passwd); do
        if id -nG "$user" 2>/dev/null | grep -qwE "reprobados|recursadores|ftpusers"; then
            userdel -f "$user" 2>/dev/null || true
        fi
    done

    # 5. Eliminar estructura
    rm -rf /srv/ftp

    # 6. Eliminar grupos
    log_info "Eliminando grupos FTP..."
    groupdel ftpusers 2>/dev/null || true
    groupdel reprobados 2>/dev/null || true
    groupdel recursadores 2>/dev/null || true

    # 7. Eliminar configuraciones extra
    rm -rf /etc/vsftpd.conf /etc/vsftpd.conf.bak /var/log/vsftpd.log /etc/ssl/private/vsftpd.pem 2>/dev/null || true

    log_success "Purgado completado. Sistema FTP limpio."
}

# ==============================================================================
# MAIN
# ==============================================================================
main() {
    check_root
    
    if [[ $# -eq 0 ]]; then
        log_info "Iniciando instalación y configuración automatizada FTP."
        instalar_paquetes
        menu_interactivo
        log_success "Proceso de automatización finalizado correctamente."
        exit 0
    fi

    case "$1" in
        -h|--help)
            mostrar_ayuda
            ;;
        -p|--purge)
            purgar_ftp
            ;;
        -c|--change-group)
            if [[ $# -ne 3 ]]; then
                echo "Error: Argumentos inválidos."
                mostrar_ayuda
                exit 1
            fi
            cambiar_grupo_usuario "$2" "$3"
            ;;
        *)
            echo "Opción desconocida: $1"
            mostrar_ayuda
            exit 1
            ;;
    esac
}

# Evitar que el script se cierre en errores dentro de la ejecución si es interactivo, 
# pero 'set -e' nos asegura que comandos críticos paren.
main "$@"

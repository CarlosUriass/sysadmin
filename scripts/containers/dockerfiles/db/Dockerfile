# ==============================================================================
# Dockerfile: Servidor de Base de Datos PostgreSQL (Alpine)
# Descripcion: Imagen personalizada con script de inicializacion y respaldo
#              automatizado hacia una carpeta del host.
# ==============================================================================

FROM postgres:16-alpine

LABEL maintainer="sysadmin-practice"
LABEL description="PostgreSQL 16 con inicializacion y respaldo automatizado"

# --- 1. Instalar cron para respaldos automatizados ---
RUN apk add --no-cache dcron

# --- 2. Copiar script de inicializacion de BD ---
COPY config/init.sql /docker-entrypoint-initdb.d/01_init.sql

# --- 3. Copiar script de respaldo ---
COPY config/backup.sh /usr/local/bin/backup.sh
RUN chmod +x /usr/local/bin/backup.sh

# --- 4. Crear directorio de respaldos dentro del contenedor ---
RUN mkdir -p /backups && chown postgres:postgres /backups

# --- 5. Configurar cron para respaldo cada 6 horas ---
RUN echo "0 */6 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1" \
    > /var/spool/cron/crontabs/postgres && \
    chown postgres:postgres /var/spool/cron/crontabs/postgres && \
    chmod 600 /var/spool/cron/crontabs/postgres

# --- 6. Exponer puerto estandar de PostgreSQL ---
EXPOSE 5432

# --- 7. Variables de entorno por defecto ---
ENV POSTGRES_DB=infraestructura
ENV POSTGRES_USER=admin
ENV POSTGRES_PASSWORD=SecureP@ss2026

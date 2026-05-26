# ==============================================================================
# Dockerfile: Servidor Web Nginx (Alpine Linux - Hardened)
# Descripcion: Imagen personalizada que elimina firmas del servidor y ejecuta
#              el proceso con un usuario no administrativo.
# ==============================================================================

FROM nginx:alpine

LABEL maintainer="sysadmin-practice"
LABEL description="Nginx hardened - sin server tokens, usuario no-root"

# --- 1. Eliminar la configuracion por defecto ---
RUN rm -f /etc/nginx/conf.d/default.conf

# --- 2. Crear usuario no-root para ejecutar Nginx ---
RUN addgroup -S webgroup && \
    adduser -S webuser -G webgroup -s /sbin/nologin

# --- 3. Copiar configuracion hardened ---
COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/default.conf /etc/nginx/conf.d/default.conf

# --- 4. Crear directorio para contenido web y asignar permisos ---
RUN mkdir -p /usr/share/nginx/html && \
    chown -R webuser:webgroup /usr/share/nginx/html && \
    chown -R webuser:webgroup /var/cache/nginx && \
    chown -R webuser:webgroup /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown webuser:webgroup /var/run/nginx.pid

# --- 5. Copiar contenido web estatico personalizado ---
COPY web_content/ /usr/share/nginx/html/

# --- 6. Exponer puerto 80 ---
EXPOSE 80

# --- 7. Ejecutar como usuario no-root ---
USER webuser

CMD ["nginx", "-g", "daemon off;"]

# Informe de Práctica: Servidor de Correo Privado y Webmail

## 1. Configuración de Identidad y DNS (Marco Teórico/Práctico)

Para que un servidor de correo sea confiable y garantice que sus mensajes no sean marcados como fraudulentos (spoofing) o spam, se requiere una configuración precisa en el proveedor de DNS.

*   **Registro MX (Mail Exchanger):** Apunta el tráfico de correo del dominio hacia el nombre del servidor (ej. `mail.reprobados.com`). 
*   **Registro A:** Relaciona el nombre del servidor `mail.reprobados.com` con la IP pública (o interna en este caso) de la máquina que hospeda los contenedores.
*   **Registro SPF (Sender Policy Framework):** Es un registro TXT que actúa como lista blanca. Ejemplo: `v=spf1 mx a ip4:192.168.1.100 -all`. Esto dice que solo la IP o los servidores MX listados tienen permiso de enviar a nombre de `reprobados.com`.
*   **Registro DKIM (DomainKeys Identified Mail):** Añade una firma criptográfica a la cabecera de los mensajes salientes. La llave pública se coloca en un registro TXT (ej. `mail._domainkey.reprobados.com`) y `docker-mailserver` (usando OpenDKIM) firma con la llave privada interna.

## 2. Sección de Orquestación y Arquitectura

El archivo `docker-compose.yml` orquesta tres servicios clave:
1.  **`mailserver`**: Ejecuta `docker-mailserver` que encapsula Postfix (SMTP), Dovecot (IMAP), Rspamd y Fail2ban. Los volúmenes persistentes como `mail_data` garantizan que los buzones no se pierdan al reiniciar.
2.  **`webmail-db`**: Una instancia de MariaDB para almacenar libretas de direcciones y configuración de sesión.
3.  **`webmail`**: El servicio de Roundcube. Se comunica con `mailserver` a través de la red interna de Docker, actuando como un intermediario proxy entre el usuario y los buzones.
4.  **`webmail-proxy`**: Un contenedor Nginx encargado de exponer Roundcube en los puertos 80 y 443, forzando la redirección a HTTPS.

## 3. Sección de Seguridad y Cifrado

El esquema de seguridad abarca varias capas:
*   **Cifrado en tránsito (TLS/SSL):** El proxy Nginx (`webmail-proxy`) se encarga de terminar el cifrado SSL. Genera automáticamente un certificado autofirmado (si no existe) y asegura que todas las credenciales ingresadas en el navegador viajen protegidas hasta el servidor.
*   **Protección de Sesión:** En `nginx.conf`, el parámetro `ssl_session_timeout 15m;` restringe la validez de la sesión SSL en inactividad.
*   **Trazabilidad (Logging):** El volumen persistente `mail_logs` monta los registros de `/var/log/mail` en el host, permitiendo auditar el flujo de conexión y transferencia.
*   **Fail2Ban:** El contenedor de correo cuenta con capacidad administrativa (`NET_ADMIN`) para modificar iptables internamente, baneando direcciones IP que fallen múltiples intentos de autenticación.

## 4. Matriz de Pruebas Extendida

### Prueba 12.1: Envío y recepción local (Cliente de Escritorio)
*   **Acción:** Configurar Thunderbird con la cuenta `director@reprobados.com` apuntando al host (IP local), usando puertos 143 (IMAP) y 587 (SMTP) con STARTTLS. Enviar un correo a `admin@reprobados.com`.
*   **Comando de ayuda para crear cuentas:** `docker exec -ti mailserver setup email add director@reprobados.com tu_contraseña`
*   **Resultado esperado:** Correo enviado y recibido sin errores.

### Prueba 12.2: Auditoría de registros (Logging)
*   **Acción:** Consultar los logs después del envío anterior.
*   **Comando:** `docker exec -ti mailserver cat /var/log/mail/mail.log` o revisar la carpeta `mail_logs` del host.
*   **Resultado esperado:** Líneas mostrando autenticación SASL exitosa y transferencia SMTP.

### Prueba 12.3: Verificación de seguridad Fail2ban
*   **Acción:** Intentar iniciar sesión por SMTP/IMAP con contraseña incorrecta más de 5 veces.
*   **Resultado esperado:** La IP desde donde se prueba (puede ser la IP de la puerta de enlace de docker) aparecerá en los logs de fail2ban y la conexión será rechazada (timeout). 
*   **Comando de verificación:** `docker exec -ti mailserver setup fail2ban`

### Prueba 13.4: Integridad de Respaldo
*   **Acción:** Borrar un correo de prueba de Roundcube, ejecutar el script `backup_mail.sh`. Eliminar el volumen `mail_data`. Descomprimir el `.tar.gz` restaurándolo en la carpeta o volumen, y volver a iniciar el contenedor.
*   **Resultado esperado:** El estado de los correos vuelve a la foto del respaldo.

### Prueba 13.5: Inicio de sesión Institucional (Webmail)
*   **Acción:** Abrir un navegador e ir a `https://localhost` o la IP del servidor. Ignorar advertencia de certificado autofirmado e iniciar sesión.
*   **Resultado esperado:** Roundcube carga correctamente la bandeja de entrada.

### Prueba 13.6: Envío de adjuntos desde Webmail
*   **Acción:** Redactar un correo a otra cuenta interna adjuntando un archivo desde el portal web.
*   **Resultado esperado:** Correo entregado con el archivo íntegro y sin errores de red.

### Prueba 13.7: Persistencia de Preferencias
*   **Acción:** Cambiar configuración de Roundcube (ej. Zona horaria o Vista), reiniciar contenedores (`docker compose restart webmail`), recargar web.
*   **Resultado esperado:** La configuración persiste gracias a `webmail-db`.

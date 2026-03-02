# Guía Rápida: Cliente FTP en la Terminal

A continuación, los comandos esenciales para navegar, administrar y transferir archivos por FTP.

## 1. Conexión Básica

```bash
ftp <IP_DEL_SERVIDOR>
```
*Ejemplo:* `ftp 192.168.1.207`

### A. Usuario Autenticado
- **Name:** *tu_usuario* (ej. carlos)
- **Password:** *tu_contraseña*
- *Permisos:* Tienes tu carpeta privada, la de tu grupo y la general. Puedes subir, descargar y crear archivos.

### B. Usuario Anónimo
- **Name:** `anonymous`
- **Password:** *(Déjalo en blanco, presiona Enter)*
- *Permisos:* Escenario de **Solo Lectura**. Únicamente ves la carpeta `general` y solo puedes **descargar** (usar `get`).

---

## 2. Navegación (Remota y Local)
La terminal interactiva maneja **dos mundos paralelos**: la pc Servidor (remota) y tu propia computadora (local). 

### 🌐 Comandos del Servidor (Remotos)
Operan en las carpetas a las que te conectaste (el servidor FTP).
- `ls` : Muestra los archivos en el servidor.
- `pwd` : Muestra en qué carpeta del servidor estás ubicado.
- `cd <carpeta>` : Te mete a una carpeta en el servidor.
- `cd ..` : Te regresa a la carpeta anterior.

### 💻 Comandos de Tu Máquina (Locales)
Comandos especiales que empiezan con **`l`** (Local). Operan en tu propia computadora.
- `!ls` o `lls` : Muestra los archivos en tu computadora.
- `!pwd` o `lpwd`: Muestra en qué carpeta local estás ubicado ("Local Print Working Directory").
- `lcd <ruta>` : Te cambia de carpeta en tu máquina ("Local Change Directory").
  - *Ejemplo*: `lcd /home/ubuntu/Documentos` significa que tus subidas *saldrán* de allí y tus descargas *caerán* allí.

---

## 3. Transferencia de Archivos (Subir / Bajar)

La regla de oro para evitar errores (como el `#553 Could not create file`) es siempre moverte primero con `cd` y `lcd` antes de transferir.

### 📥 Descargar (GET)
*Trae archivos del servidor hacia mi computadora.*
```ftp
ftp> cd general              # (Paso 1: Ve a donde está el archivo en el servidor)
ftp> lcd /home/ubuntu        # (Paso 2: Dile a tu PC dónde lo vas a recibir)
ftp> get tarea.txt           # (Paso 3: Descarga el archivo)
```

### 📤 Subir (PUT)
*Lleva archivos de mi computadora hacia el servidor.*
```ftp
ftp> cd carlos               # (Paso 1: Ve a tu carpeta privada en el servidor)
ftp> lcd /home/ubuntu        # (Paso 2: Ve a donde tienes guardado el archivo en tu PC)
ftp> put proyecto.pdf        # (Paso 3: Sube el archivo)
```

---

## 4. Opciones Extra
- `mkdir <nombre>` : Crear nueva carpeta en servidor.
- `delete <archivo>` : Borrar un archivo del servidor.
- `mput *` y `mget *` : Subir o descargar **múltiples** archivos a la vez. (Usa `prompt` antes para no tener que oprimir "yes" mil veces).
- `quit` o `bye` o `exit` : Desconectarte del servidor y cerrar FTP.

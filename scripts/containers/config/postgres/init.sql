-- ==============================================================================
-- Script: init.sql
-- Descripcion: Inicializacion de la base de datos 'infraestructura'
--              Crea la tabla de usuarios y registros de prueba.
-- ==============================================================================

-- La base de datos 'infraestructura' ya se crea via POSTGRES_DB env var.
-- Este script opera dentro de esa base de datos.

-- Tabla de usuarios del sistema
CREATE TABLE IF NOT EXISTS usuarios (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    nombre      VARCHAR(100) NOT NULL,
    email       VARCHAR(100),
    grupo       VARCHAR(30)  NOT NULL DEFAULT 'general',
    activo      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de registro de accesos (auditoria basica)
CREATE TABLE IF NOT EXISTS accesos (
    id          SERIAL PRIMARY KEY,
    usuario_id  INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
    servicio    VARCHAR(30) NOT NULL,
    ip_origen   INET,
    fecha       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de archivos subidos via FTP
CREATE TABLE IF NOT EXISTS archivos_ftp (
    id          SERIAL PRIMARY KEY,
    nombre      VARCHAR(255) NOT NULL,
    tamano_kb   INTEGER,
    subido_por  INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
    fecha       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Registros de prueba
INSERT INTO usuarios (username, nombre, email, grupo) VALUES
    ('jperez',    'Juan Perez',     'jperez@infra.local',    'reprobados'),
    ('mgarcia',   'Maria Garcia',   'mgarcia@infra.local',   'recursadores'),
    ('alopez',    'Ana Lopez',      'alopez@infra.local',    'general'),
    ('crodriguez','Carlos Rodriguez','crodriguez@infra.local','reprobados'),
    ('lmartinez', 'Laura Martinez', 'lmartinez@infra.local', 'recursadores')
ON CONFLICT (username) DO NOTHING;

-- Registros de acceso de prueba
INSERT INTO accesos (usuario_id, servicio, ip_origen) VALUES
    (1, 'ftp',  '172.20.0.1'),
    (2, 'web',  '172.20.0.1'),
    (3, 'web',  '172.20.0.1'),
    (1, 'ftp',  '172.20.0.1'),
    (4, 'web',  '172.20.0.1')
ON CONFLICT DO NOTHING;

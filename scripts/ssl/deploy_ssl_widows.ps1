# ==============================================================================
# Script: deploy_ssl_windows.ps1
# Descripción: Aprovisionamiento híbrido (Web/FTP), cifrado SSL/TLS y
#              validación de integridad (Práctica 7) - Windows Server
# ==============================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ==============================================================================
# VARIABLES GLOBALES
# ==============================================================================
$SCRIPT_DIR   = Split-Path -Parent $MyInvocation.MyCommand.Path

$FTP_SERVER   = "192.168.100.11"
$FTP_USER     = "usuario"
$FTP_PASS     = "pass"
$DOMAIN       = "www.reprobados.com"
$CERT_DIR     = "C:\SSL\reprobados"
$CERT_FILE    = "$CERT_DIR\server.crt"
$KEY_FILE     = "$CERT_DIR\server.key"
$PFX_FILE     = "$CERT_DIR\server.pfx"
$PFX_PASS     = "changeit"

# ==============================================================================
# LOGGING & UTILIDADES
# ==============================================================================
function Log-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Log-Success { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Log-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Log-Error   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Test-OpenSSL {
    # Busca openssl en PATH o en rutas comunes (Git for Windows, Win32-OpenSSL)
    $candidates = @(
        "openssl",
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    )
    foreach ($c in $candidates) {
        if (Get-Command $c -ErrorAction SilentlyContinue) { return $c }
    }
    Log-Error "No se encontró OpenSSL. Instálalo o agrégalo al PATH."
    exit 1
}

# ==============================================================================
# LÓGICA DE SSL/TLS
# ==============================================================================
function Generate-SslCert {
    if (-not (Test-Path $CERT_DIR)) {
        New-Item -ItemType Directory -Path $CERT_DIR -Force | Out-Null
    }

    if (-not (Test-Path $CERT_FILE) -or -not (Test-Path $KEY_FILE)) {
        $openssl = Test-OpenSSL
        Log-Info "Generando certificado autofirmado para $DOMAIN..."

        $subj = "/C=MX/ST=Sinaloa/L=Culiacan/O=UAS/OU=FIM/CN=$DOMAIN"
        & $openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
            -keyout $KEY_FILE -out $CERT_FILE `
            -subj $subj 2>$null

        # Generar también PFX para IIS y otros servicios Windows que lo requieren
        & $openssl pkcs12 -export `
            -in $CERT_FILE -inkey $KEY_FILE `
            -out $PFX_FILE `
            -password "pass:$PFX_PASS" 2>$null

        Log-Success "Certificado SSL generado (CRT + KEY + PFX)."
    } else {
        Log-Info "El certificado SSL ya existe. Reutilizando."
    }
}

function Ask-SSL {
    param([string]$Svc)
    $resp = Read-Host "¿Desea activar SSL en el servicio $Svc? [S/N]"
    if ($resp -match "^[Ss]$") {
        Generate-SslCert
        return $true
    }
    return $false
}

function Ask-Ports {
    param(
        [string]$Svc,
        [int]$DefaultHttp,
        [int]$DefaultHttps,
        [bool]$SslEnabled
    )

    $inputHttp = Read-Host "Puerto HTTP para $Svc [default: $DefaultHttp]"
    $script:PORT_HTTP = if ($inputHttp -match '^\d+$') { [int]$inputHttp } else { $DefaultHttp }

    if ($SslEnabled) {
        $inputHttps = Read-Host "Puerto HTTPS (SSL) para $Svc [default: $DefaultHttps]"
        $script:PORT_HTTPS = if ($inputHttps -match '^\d+$') { [int]$inputHttps } else { $DefaultHttps }
    } else {
        $script:PORT_HTTPS = $DefaultHttps
    }
}

# ==============================================================================
# LÓGICA FTP Y HASH (Integridad)
# ==============================================================================
function Download-FromFtp {
    param(
        [string]$Service,
        [string]$Kind   # "http" o "ftp"
    )

    $os      = "Windows"
    $baseUrl = "ftp://${FTP_SERVER}/${Kind}/${os}/${Service}"
    $cred    = [System.Net.NetworkCredential]::new($FTP_USER, $FTP_PASS)

    Log-Info "Conectando al FTP para buscar versiones de $Service..."

    # Listar archivos disponibles
    try {
        $ftpList         = [System.Net.WebRequest]::Create("$baseUrl/") -as [System.Net.FtpWebRequest]
        $ftpList.Method  = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $ftpList.Credentials = $cred
        $ftpList.EnableSsl   = $false

        $response  = $ftpList.GetResponse()
        $reader    = New-Object System.IO.StreamReader($response.GetResponseStream())
        $rawList   = $reader.ReadToEnd().Trim() -split "`r?`n"
        $reader.Close(); $response.Close()
    } catch {
        Log-Error "No se pudo conectar al repositorio FTP: $_"
        return $null
    }

    # Filtrar hashes
    $installers = $rawList | Where-Object { $_ -notmatch '\.(sha256|md5)$' -and $_ -ne "" }

    if ($installers.Count -eq 0) {
        Log-Error "No se encontraron instaladores en el FTP para $Service."
        return $null
    }

    Write-Host "Versiones disponibles para ${Service}:"
    for ($i = 0; $i -lt $installers.Count; $i++) {
        Write-Host "  $($i+1)) $($installers[$i])"
    }

    $sel = Read-Host "Seleccione el número del archivo a descargar"
    if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $installers.Count) {
        Log-Error "Selección inválida."
        return $null
    }

    $chosen    = $installers[[int]$sel - 1]
    $localFile = "$env:TEMP\$chosen"
    $hashFile  = "$localFile.sha256"

    # --- Descargar instalador ---
    Log-Info "Descargando $chosen desde FTP..."
    try {
        $ftpDl            = [System.Net.WebRequest]::Create("$baseUrl/$chosen") -as [System.Net.FtpWebRequest]
        $ftpDl.Method     = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        $ftpDl.Credentials = $cred
        $dlResp           = $ftpDl.GetResponse()
        $dlStream         = $dlResp.GetResponseStream()
        $fileStream       = [System.IO.File]::Create($localFile)
        $dlStream.CopyTo($fileStream)
        $fileStream.Close(); $dlStream.Close(); $dlResp.Close()
    } catch {
        Log-Error "Error al descargar el instalador: $_"
        return $null
    }

    # --- Descargar y verificar hash SHA256 ---
    Log-Info "Descargando comprobación de hash (${chosen}.sha256)..."
    try {
        $ftpHash            = [System.Net.WebRequest]::Create("$baseUrl/${chosen}.sha256") -as [System.Net.FtpWebRequest]
        $ftpHash.Method     = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        $ftpHash.Credentials = $cred
        $hashResp           = $ftpHash.GetResponse()
        $hashStream         = $hashResp.GetResponseStream()
        $hashFileStream     = [System.IO.File]::Create($hashFile)
        $hashStream.CopyTo($hashFileStream)
        $hashFileStream.Close(); $hashStream.Close(); $hashResp.Close()

        Log-Info "Verificando integridad del archivo..."
        $expectedHash = (Get-Content $hashFile -Raw).Trim().Split(" ")[0].ToLower()
        $actualHash   = (Get-FileHash $localFile -Algorithm SHA256).Hash.ToLower()

        if ($expectedHash -eq $actualHash) {
            Log-Success "Verificación Hash exitosa (SHA256 coincide)."
        } else {
            Log-Error "Fallo en verificación de Hash. El archivo puede estar corrupto."
            Remove-Item $localFile, $hashFile -ErrorAction SilentlyContinue
            return $null
        }
    } catch {
        Log-Warn "No se encontró archivo de hash .sha256 en el servidor. Saltando verificación."
    }

    return $localFile
}

# ==============================================================================
# INSTALACIONES ESPECÍFICAS
# ==============================================================================

# ------------------------------------------------------------------------------
# IIS (equivalente a Apache/Nginx en Windows Server)
# ------------------------------------------------------------------------------
function Install-IIS-SSL {
    param([string]$Source)
    Log-Info "Iniciando instalación de IIS..."

    $sslEnabled = Ask-SSL -Svc "IIS"
    Ask-Ports -Svc "IIS" -DefaultHttp 80 -DefaultHttps 443 -SslEnabled $sslEnabled

    if ($Source -eq "FTP") {
        # En Windows, IIS se activa por roles, no hay instalador FTP tradicional.
        # Descargamos un paquete extra desde FTP si aplica (ej: módulos adicionales).
        Log-Warn "IIS se instala como rol de Windows. El origen FTP aplica solo para módulos adicionales."
    }

    Log-Info "Instalando rol IIS mediante Install-WindowsFeature..."
    # Llamar al script de la Práctica 6 equivalente en Windows
    & "$SCRIPT_DIR\..\http\http_deploy.ps1" -Service iis -Port $script:PORT_HTTP

    if ($sslEnabled) {
        Log-Info "Importando certificado PFX en el almacén de IIS..."
        $pfxPass = ConvertTo-SecureString -String $PFX_PASS -AsPlainText -Force
        $cert    = Import-PfxCertificate -FilePath $PFX_FILE `
                       -CertStoreLocation "Cert:\LocalMachine\My" `
                       -Password $pfxPass

        Import-Module WebAdministration -ErrorAction SilentlyContinue

        # Binding HTTPS
        $siteName = "Default Web Site"
        $thumb    = $cert.Thumbprint

        if (-not (Get-WebBinding -Name $siteName -Port $script:PORT_HTTPS -Protocol "https" -ErrorAction SilentlyContinue)) {
            New-WebBinding -Name $siteName -Protocol "https" -Port $script:PORT_HTTPS -SslFlags 0
        }

        # Asignar certificado al binding
        $binding = Get-WebBinding -Name $siteName -Protocol "https" -Port $script:PORT_HTTPS
        $binding.AddSslCertificate($thumb, "My")

        # Redirigir HTTP → HTTPS mediante URL Rewrite (si está instalado)
        $webConfig = "C:\inetpub\wwwroot\web.config"
        if (-not (Test-Path $webConfig)) {
            Set-Content $webConfig "<?xml version=`"1.0`" encoding=`"UTF-8`"?><configuration></configuration>"
        }
        [xml]$xml = Get-Content $webConfig
        # Agregar regla HSTS
        $httpProtocol = $xml.SelectSingleNode("//system.webServer/httpProtocol")
        if (-not $httpProtocol) {
            $sysWeb      = $xml.SelectSingleNode("//configuration")
        if (-not $sysWeb) { $sysWeb = $xml.DocumentElement }
            $httpProtocol = $xml.CreateElement("httpProtocol")
            $sysWeb.AppendChild($httpProtocol) | Out-Null
        }
        $customHeaders = $xml.SelectSingleNode("//system.webServer/httpProtocol/customHeaders")
        if (-not $customHeaders) {
            $customHeaders = $xml.CreateElement("customHeaders")
            $httpProtocol.AppendChild($customHeaders) | Out-Null
        }
        $hstsHeader = $xml.CreateElement("add")
        $hstsHeader.SetAttribute("name", "Strict-Transport-Security")
        $hstsHeader.SetAttribute("value", "max-age=63072000; includeSubDomains")
        $customHeaders.AppendChild($hstsHeader) | Out-Null
        $xml.Save($webConfig)

        Log-Success "IIS configurado con SSL en puerto $($script:PORT_HTTPS) y HSTS habilitado."
    }

    Restart-Service W3SVC
    Set-Service W3SVC -StartupType Automatic
    Log-Success "IIS instalado y configurado."
}

# ------------------------------------------------------------------------------
# Apache
# ------------------------------------------------------------------------------
function Install-Apache-SSL {
    param([string]$Source)
    Log-Info "Iniciando instalación de Apache..."

    if ($Source -eq "FTP") { Log-Warn "Aviso: la automatización para Apache suele provenir del repositorio WEB oficial." }

    $sslEnabled = Ask-SSL -Svc "Apache"
    Ask-Ports -Svc "Apache" -DefaultHttp 80 -DefaultHttps 443 -SslEnabled $sslEnabled

    Log-Info "Instalando servicio Apache base mediante http_deploy.ps1..."
    & "$SCRIPT_DIR\..\http\http_deploy.ps1" -Service apache -Port $script:PORT_HTTP

    if ($sslEnabled) {
        $apacheConf = "C:\tools\Apache24\conf\httpd.conf"
        if (Test-Path $apacheConf) {
            Log-Info "Configurando SSL y forzando HSTS en Apache..."
            $confContent = Get-Content $apacheConf -Raw

            $confContent = $confContent -replace '#LoadModule ssl_module', 'LoadModule ssl_module'
            $confContent = $confContent -replace '#LoadModule rewrite_module', 'LoadModule rewrite_module'
            $confContent = $confContent -replace '#LoadModule headers_module', 'LoadModule headers_module'
            $confContent = $confContent -replace '#LoadModule socache_shmcb_module', 'LoadModule socache_shmcb_module'
            $confContent = $confContent -replace '(?s)# --- INIT SSL ---.*# --- END SSL ---', ''

            $cPath = $CERT_FILE -replace "\\", "/"
            $kPath = $KEY_FILE -replace "\\", "/"

            $vhostSsl = @"

# --- INIT SSL ---
<VirtualHost *:$($script:PORT_HTTP)>
    ServerName $DOMAIN
    Redirect permanent / https://${FTP_SERVER}:$($script:PORT_HTTPS)/
</VirtualHost>

Listen $($script:PORT_HTTPS)
<VirtualHost _default_:$($script:PORT_HTTPS)>
    ServerName $DOMAIN
    DocumentRoot "C:/tools/Apache24/htdocs"
    SSLEngine on
    SSLCertificateFile "$cPath"
    SSLCertificateKeyFile "$kPath"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains;"
</VirtualHost>
# --- END SSL ---
"@
            $confContent += $vhostSsl
            
            [IO.File]::WriteAllText($apacheConf, $confContent, [Text.UTF8Encoding]::new($false))
            Restart-Service Apache2.4 -ErrorAction SilentlyContinue
            Log-Success "Apache configurado con SSL y HSTS."
        }
    }
    Log-Success "Apache instalado y configurado."
}

# ------------------------------------------------------------------------------
# Nginx
# ------------------------------------------------------------------------------
function Install-Nginx-SSL {
    param([string]$Source)
    Log-Info "Iniciando instalación de Nginx..."

    if ($Source -eq "FTP") { Log-Warn "Aviso: la automatización para Nginx suele provenir del repositorio WEB oficial." }

    $sslEnabled = Ask-SSL -Svc "Nginx"
    Ask-Ports -Svc "Nginx" -DefaultHttp 80 -DefaultHttps 443 -SslEnabled $sslEnabled

    Log-Info "Instalando servicio Nginx base mediante http_deploy.ps1..."
    & "$SCRIPT_DIR\..\http\http_deploy.ps1" -Service nginx -Port $script:PORT_HTTP

    if ($sslEnabled) {
        $nginxConf = "C:\tools\nginx\conf\nginx.conf"
        if (Test-Path $nginxConf) {
            Log-Info "Configurando SSL y forzando HSTS en Nginx..."
            
            $cPath = $CERT_FILE -replace "\\", "/"
            $kPath = $KEY_FILE -replace "\\", "/"

            $newNginxConf = @"
worker_processes  1;
events { worker_connections  1024; }

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       $($script:PORT_HTTP);
        server_name  $DOMAIN;
        return 301 https://${FTP_SERVER}:$($script:PORT_HTTPS)`$request_uri;
    }

    server {
        listen       $($script:PORT_HTTPS) ssl http2;
        server_name  $DOMAIN;

        ssl_certificate      "$cPath";
        ssl_certificate_key  "$kPath";

        add_header Strict-Transport-Security "max-age=63072000; includeSubdomains" always;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
"@
            [IO.File]::WriteAllText($nginxConf, $newNginxConf, [Text.UTF8Encoding]::new($false))
            
            Stop-Process -Name nginx -Force -EA SilentlyContinue
            Start-Sleep 1
            Push-Location "C:\tools\nginx"
            Start-Process -FilePath ".\nginx.exe" -NoNewWindow
            Pop-Location
            Log-Success "Nginx configurado con SSL y HSTS."
        }
    }
    Log-Success "Nginx instalado y configurado."
}

# ------------------------------------------------------------------------------
# Tomcat (igual que en Linux, existe para Windows)
# ------------------------------------------------------------------------------
function Install-Tomcat-SSL {
    param([string]$Source)
    Log-Info "Iniciando instalación de Tomcat..."

    $localFile = $null
    if ($Source -eq "FTP") {
        $localFile = Download-FromFtp -Service "tomcat" -Kind "http"
        if (-not $localFile) { return }
    }

    $sslEnabled = Ask-SSL -Svc "Tomcat"
    Ask-Ports -Svc "Tomcat" -DefaultHttp 8080 -DefaultHttps 8443 -SslEnabled $sslEnabled

    Log-Info "Instalando Tomcat base mediante http_deploy.ps1..."
    & "$SCRIPT_DIR\..\http\http_deploy.ps1" -Service tomcat -Port $script:PORT_HTTP

    if ($sslEnabled) {
        Log-Info "Configurando SSL en Tomcat (Keystore PKCS12 desde PEM)..."
        $openssl = Test-OpenSSL

        $pkcs12File = "$CERT_DIR\tomcat.p12"
        & $openssl pkcs12 -export `
            -in $CERT_FILE -inkey $KEY_FILE `
            -out $pkcs12File -name tomcat `
            -password "pass:$PFX_PASS" 2>$null

        # Detectar server.xml según si es instalación APT-like (winget/msi) o tarball
        $serverXmlPaths = @(
            "C:\Program Files\Apache Software Foundation\Tomcat*\conf\server.xml",
            "C:\tomcat\conf\server.xml",
            "C:\opt\tomcat\conf\server.xml"
        )

        $serverXml = $null
        foreach ($pattern in $serverXmlPaths) {
            $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { $serverXml = $found.FullName; break }
        }

        if (-not $serverXml) {
            Log-Warn "No se encontró server.xml de Tomcat. Configura el conector SSL manualmente."
            Log-Info "Conector a agregar en server.xml:"
            Write-Host @"
<Connector port="$($script:PORT_HTTPS)"
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true"
           scheme="https" secure="true"
           keystoreFile="$pkcs12File"
           keystorePass="$PFX_PASS"
           clientAuth="false" sslProtocol="TLS" />
"@ -ForegroundColor Gray
        } else {
            [xml]$xml = Get-Content $serverXml
            $service  = $xml.SelectSingleNode("//Service[@name='Catalina']")
            if ($service) {
                $connector = $xml.CreateElement("Connector")
                $connector.SetAttribute("port",          $script:PORT_HTTPS)
                $connector.SetAttribute("protocol",      "org.apache.coyote.http11.Http11NioProtocol")
                $connector.SetAttribute("maxThreads",    "150")
                $connector.SetAttribute("SSLEnabled",    "true")
                $connector.SetAttribute("scheme",        "https")
                $connector.SetAttribute("secure",        "true")
                $connector.SetAttribute("keystoreFile",  $pkcs12File)
                $connector.SetAttribute("keystorePass",  $PFX_PASS)
                $connector.SetAttribute("clientAuth",    "false")
                $connector.SetAttribute("sslProtocol",   "TLS")
                $service.AppendChild($connector) | Out-Null
                $xml.Save($serverXml)
                Log-Success "Conector SSL agregado a server.xml."
            }
            # Reiniciar servicio Tomcat (si está registrado como servicio Windows)
            $tomcatSvc = Get-Service -Name "Tomcat*" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($tomcatSvc) { Restart-Service $tomcatSvc.Name }
            else { Log-Warn "Servicio Tomcat no encontrado. Reinícialo manualmente." }
        }
    }
    Log-Success "Tomcat instalado y configurado."
}

# ------------------------------------------------------------------------------
# FileZilla Server / IIS FTP (equivalente a vsftpd)
# ------------------------------------------------------------------------------
function Install-FtpServer-SSL {
    param([string]$Source)
    Log-Info "Iniciando instalación de servidor FTP..."

    $localFile = $null
    if ($Source -eq "FTP") {
        $localFile = Download-FromFtp -Service "filezilla-server" -Kind "ftp"
        if (-not $localFile) { return }
    }

    $sslEnabled = Ask-SSL -Svc "FTP Server"

    if ($Source -eq "FTP" -and $localFile) {
        Log-Info "Instalando FileZilla Server desde paquete FTP..."
        Start-Process -FilePath $localFile -ArgumentList "/S" -Wait
    } else {
        Log-Info "Activando FTP mediante rol IIS-FTP (Windows Server)..."
        Install-WindowsFeature Web-Ftp-Server -IncludeAllSubFeature -ErrorAction SilentlyContinue | Out-Null
        # Llamar al script ftp.ps1
        if (Test-Path "$SCRIPT_DIR\..\ftp\ftp.ps1") {
            & "$SCRIPT_DIR\..\ftp\ftp.ps1"
        }
    }

    if ($sslEnabled) {
        Log-Info "Configurando SSL (FTPS explícito) en el servidor FTP..."
        $pfxPass = ConvertTo-SecureString -String $PFX_PASS -AsPlainText -Force
        $cert    = Import-PfxCertificate -FilePath $PFX_FILE `
                       -CertStoreLocation "Cert:\LocalMachine\My" `
                       -Password $pfxPass

        Import-Module WebAdministration -ErrorAction SilentlyContinue

        # Configurar SSL en el sitio FTP de IIS
        $ftpSite = Get-WebSite | Where-Object { $_.Bindings.Collection.Protocol -contains "ftp" } | Select-Object -First 1
        if ($ftpSite) {
            Set-ItemProperty "IIS:\Sites\$($ftpSite.Name)" `
                -Name "ftpServer.security.ssl.serverCertHash" `
                -Value $cert.Thumbprint

            Set-ItemProperty "IIS:\Sites\$($ftpSite.Name)" `
                -Name "ftpServer.security.ssl.controlChannelPolicy" `
                -Value "SslAllow"   # o "SslRequire" para FTPS estricto

            Set-ItemProperty "IIS:\Sites\$($ftpSite.Name)" `
                -Name "ftpServer.security.ssl.dataChannelPolicy" `
                -Value "SslAllow"

            Log-Success "SSL configurado en sitio FTP: $($ftpSite.Name)"
        } else {
            Log-Warn "No se encontró un sitio FTP activo en IIS. Configura el certificado manualmente."
            Log-Info "Thumbprint del certificado: $($cert.Thumbprint)"
        }
    }

    Log-Success "Servidor FTP instalado y configurado."
}

# ==============================================================================
# MAIN
# ==============================================================================
function Main {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  ORQUESTADOR DE DESPLIEGUE HÍBRIDO CON SSL/TLS (Práctica 7)" -ForegroundColor White
    Write-Host "  Windows Server Edition" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "Servicios disponibles:"
    Write-Host "  1) IIS       (HTTP/HTTPS - equivalente Apache/Nginx)"
    Write-Host "  2) Apache    (HTTP/HTTPS)"
    Write-Host "  3) Nginx     (HTTP/HTTPS)"
    Write-Host "  4) Tomcat    (HTTP/HTTPS)"
    Write-Host "  5) FTP Server (FTPS - equivalente vsftpd)"

    $sOpt = Read-Host "Seleccione un servicio (1-5)"
    $svc  = switch ($sOpt) {
        "1" { "iis" }
        "2" { "apache" }
        "3" { "nginx" }
        "4" { "tomcat" }
        "5" { "ftp" }
        default { Log-Error "Opción inválida."; exit 1 }
    }

    Write-Host "============================================================"
    Write-Host "Fuente de Instalación para ${svc}:"
    Write-Host "  1) WEB (winget / roles de Windows / chocolatey)"
    Write-Host "  2) FTP (Repositorio Privado con validación SHA256)"
    $mOpt   = Read-Host "Seleccione fuente (1-2)"
    $source = switch ($mOpt) {
        "1" { "WEB" }
        "2" { "FTP" }
        default { Log-Error "Opción inválida."; exit 1 }
    }

    Write-Host "============================================================"
    Log-Info "Instalando $svc mediante $source..."

    switch ($svc) {
        "iis"    { Install-IIS-SSL    -Source $source }
        "apache" { Install-Apache-SSL -Source $source }
        "nginx"  { Install-Nginx-SSL  -Source $source }
        "tomcat" { Install-Tomcat-SSL -Source $source }
        "ftp"    { Install-FtpServer-SSL -Source $source }
    }

    Write-Host "============================================================"
    Log-Info "Resumen de puertos activos:"
    # Equivalente a: ss -tlnp
    netstat -ano | Select-String ":80|:443|:8443|:21|:990"
    Log-Success "Proceso de orquestación completado."
}

Main
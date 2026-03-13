# Requires -RunAsAdministrator

param(
    [string]$Service = "",
    [int]$Port = 0,
    [string]$ServiceVersion = "",
    [alias("Version")]$V,
    [switch]$ListVersions,
    [switch]$Status,
    [switch]$Purge,
    [switch]$Help
)

# ==============================================================================
# UTILS & LOGGING
# ==============================================================================

function Write-LogInfo ([string]$Message) {
    Write-Host "[INFO] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Cyan
}

function Write-LogSuccess ([string]$Message) {
    Write-Host "[OK]   $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Green
}

function Write-LogWarn ([string]$Message) {
    Write-Host "[WARN] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Yellow
}

function Write-LogError ([string]$Message) {
    Write-Host "[FAIL] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Red
}

function Test-PortInUse {
    param([int]$Port)
    $tcp = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    return ([bool]$tcp)
}

function Get-NearbyAvailablePorts {
    param([int]$Port)
    $suggestions = @()
    for ($i = $Port + 1; $i -le $Port + 20 -and $i -le 65535; $i++) {
        if (-not (Test-PortInUse -Port $i)) {
            $suggestions += $i
            if ($suggestions.Count -ge 3) { break }
        }
    }
    return $suggestions
}

# ==============================================================================
# SECURITY & HARDENING
# ==============================================================================

function Set-ServiceUserAndPermissions {
    param([string]$ServiceName, [string]$Path)
    $User = "svc_$ServiceName"
    Write-LogInfo "Configurando aislamiento de usuario para $ServiceName ($User)..."
    
    if (-not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
        $Pass = ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force
        New-LocalUser -Name $User -Password $Pass -Description "Dedicated Service User for $ServiceName" | Out-Null
    }

    if (Test-Path $Path) {
        $acl = Get-Acl $Path
        # Deshabilitar herencia y copiar permisos actuales
        $acl.SetAccessRuleProtection($true, $true)
        # Limpiar permisos de 'Users' comunes si existen para mayor seguridad
        $rules = $acl.Access | Where-Object { $_.IdentityReference -match "Users" }
        foreach ($r in $rules) { $acl.RemoveAccessRule($r) | Out-Null }
        
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($User, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl $Path $acl
    }
}

function Apply-IISHardening {
    Write-LogInfo "Aplicando Hardening a IIS (Server Tokens, Request Filtering)..."
    Import-Module WebAdministration
    # 1. Eliminar X-Powered-By
    $filter = "system.webServer/httpProtocol/customHeaders"
    $headers = Get-WebConfigurationProperty -Filter $filter -Name "."
    $headerToRemove = $headers.Collection | Where-Object { $_.name -eq "X-Powered-By" }
    if ($headerToRemove) {
        Remove-WebConfigurationProperty -Filter $filter -Name "." -AtElement @{name="X-Powered-By"}
    }

    # 2. Agregar encabezados de seguridad
    Set-WebConfigurationProperty -filter $filter -name "." -value @{name='X-Frame-Options';value='SAMEORIGIN'} -ErrorAction SilentlyContinue
    Set-WebConfigurationProperty -filter $filter -name "." -value @{name='X-Content-Type-Options';value='nosniff'} -ErrorAction SilentlyContinue

    # 3. Request Filtering (Ocultar versión y restringir métodos)
    Set-WebConfigurationProperty -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value $true -ErrorAction SilentlyContinue
    
    # Restringir Métodos Peligrosos (TRACE, TRACK)
    $verbFilter = "system.webServer/security/requestFiltering/verbs"
    Add-WebConfigurationProperty -filter $verbFilter -name "." -value @{verb='TRACE';allowed=$false} -ErrorAction SilentlyContinue
    Add-WebConfigurationProperty -filter $verbFilter -name "." -value @{verb='TRACK';allowed=$false} -ErrorAction SilentlyContinue
}

function Set-FirewallRule {
    param([int]$Port, [string]$Svc)
    $Name = "HTTP-Allow-$Svc-$Port"
    Write-LogInfo "Configurando Firewall para puerto $Port ($Svc)..."
    if (-not (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $Name -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    }
}

# ==============================================================================
# INSTALLATION & CONFIGURATION
# ==============================================================================

function Generate-IndexHtml {
    param([string]$Path, [string]$Svc, [string]$Ver, [int]$Port)
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # El script deberá crear una página index.html personalizada: "Servidor: [Nombre del Servicio] - Versión: [Versión Elegida] - Puerto: [Puerto]"
    $Content = "<h1>Servidor: $Svc - Versión: $Ver - Puerto: $Port</h1><p>Aprovisionamiento Automatizado - Windows (Práctica 6)</p><p>Fecha: $Time</p>"
    $Content | Set-Content -Path $Path -Encoding UTF8
    Write-LogSuccess "Página index.html generada en $Path"
}

function Get-DynamicVersions {
    param([string]$Service)
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-LogWarn "Instalando Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
    }
    $versions = @()
    switch ($Service.ToLower()) {
        "iis" { $versions = @("10.0 (Win Server Default)") }
        "apache" {
            $chocoOut = choco search apache-httpd --exact --all-versions | Select-String "apache-httpd\s+\d"
            foreach ($line in $chocoOut) { $versions += ($line.ToString() -split '\s+')[1] }
        }
        "nginx" {
            $chocoOut = choco search nginx --exact --all-versions | Select-String "nginx\s+\d"
            foreach ($line in $chocoOut) { $versions += ($line.ToString() -split '\s+')[1] }
        }
    }
    if ($versions.Count -eq 0) {
        if ($Service -eq "apache") { $versions = @("2.4.58", "2.4.55") }
        if ($Service -eq "nginx") { $versions = @("1.27.4", "1.26.3") }
    }
    return $versions | Select-Object -First 5
}

function Install-WebServer {
    param([string]$Service, [int]$Port, [string]$Version)
    Write-LogInfo "Iniciando despliegue de $Service ($Version) en puerto $Port..."
    
    if (Test-PortInUse -Port $Port) {
        $suggestions = Get-NearbyAvailablePorts -Port $Port
        $msg = "Error: El puerto $Port ya esta en uso."
        if ($suggestions.Count -gt 0) { $msg += " Puertos recomendados: $($suggestions -join ', ')" }
        Write-LogError $msg
        throw $msg
    }

    switch ($Service.ToLower()) {
        "iis" {
            $features = @("IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures", "IIS-DefaultDocument", "IIS-StaticContent", "IIS-RequestFiltering")
            foreach ($f in $features) { Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null }
            Import-Module WebAdministration
            Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" -PropertyName BindingInformation -Value "*:$($Port):" -ErrorAction SilentlyContinue | Out-Null
            Apply-IISHardening
            Generate-IndexHtml -Path "C:\inetpub\wwwroot\index.html" -Svc "IIS" -Ver $Version -Port $Port
            # IIS usa el ApplicationPool Identity por defecto, pero configuramos permisos de usuario para aislamiento
            Set-ServiceUserAndPermissions -ServiceName "iis" -Path "C:\inetpub\wwwroot"
            Start-Service W3SVC -ErrorAction SilentlyContinue
        }
        "nginx" {
            choco install nginx --version=$Version -y | Out-Null
            $path = "C:\tools\nginx" # Ruta estándar de choco
            $conf = "$path\conf\nginx.conf"
            (Get-Content $conf) -replace 'listen\s+80;', "listen $Port;" `
                                -replace 'server_tokens\s+\w+;', "server_tokens off;" | Set-Content $conf
            # Agregar encabezados de seguridad a nginx.conf si no existen
            if (-not (Select-String "add_header X-Frame-Options" $conf)) {
                $c = Get-Content $conf
                $c = $c -replace 'server {', "server {`n        add_header X-Frame-Options SAMEORIGIN;`n        add_header X-Content-Type-Options nosniff;"
                $c | Set-Content $conf
            }
            Set-ServiceUserAndPermissions -ServiceName "nginx" -Path "$path\html"
            Generate-IndexHtml -Path "$path\html\index.html" -Svc "Nginx" -Ver $Version -Port $Port
            if (-not (Get-Service nginx -ErrorAction SilentlyContinue)) {
                New-Service -Name "nginx" -BinaryPathName "$path\nginx.exe" -StartupType Automatic | Out-Null
            }
            Restart-Service nginx -Force -ErrorAction SilentlyContinue
        }
        "apache" {
            choco install apache-httpd --version=$Version -y | Out-Null
            $path = "C:\tools\apache24"
            $conf = "$path\conf\httpd.conf"
            $c = Get-Content $conf
            $c = $c -replace 'Listen 80', "Listen $Port" -replace 'ServerTokens \w+', "ServerTokens Prod" -replace 'ServerSignature \w+', "ServerSignature Off"
            # Ocultar Headers y Seguridad
            $c += "`nHeader set X-Frame-Options SAMEORIGIN"
            $c += "`nHeader set X-Content-Type-Options nosniff"
            $c | Set-Content $conf
            Set-ServiceUserAndPermissions -ServiceName "apache" -Path "$path\htdocs"
            Generate-IndexHtml -Path "$path\htdocs\index.html" -Svc "Apache" -Ver $Version -Port $Port
            Restart-Service Apache* -Force -ErrorAction SilentlyContinue
        }
    }
    Set-FirewallRule -Port $Port -Svc $Service
    Write-LogSuccess "Servicio $Service desplegado con éxito en puerto $Port."
}

# ==============================================================================
# MAIN INTERFACE
# ==============================================================================

function Show-Status {
    Write-Host "`n--- ESTADO DE SERVICIOS (WINDOWS) ---" -ForegroundColor White
    Get-Service -Name W3SVC, Apache*, nginx -ErrorAction SilentlyContinue | Select-Object Name, Status | FT -Auto
}

function Request-ValidPort {
    while ($true) {
        Write-Host "Ingrese puerto (1024-65535, 80): " -ForegroundColor Cyan -NoNewline
        $pStr = Read-Host
        $p = 0
        if ([int]::TryParse($pStr, [ref]$p)) {
            if ($p -eq 80 -or ($p -ge 1024 -and $p -le 65535)) {
                if (-not (Test-PortInUse -Port $p)) { return $p }
                Write-LogError "Puerto $p ocupado."
            } else { Write-LogWarn "Puerto inválido o reservado." }
        }
    }
}

function Main {
    if ($Help) {
        Write-Host "Uso: .\http_deploy.ps1 [-Service iis|apache|nginx] [-Port <num>] [-Version <ver>] [-ListVersions] [-Status] [-Purge]"
        return
    }

    if ($Status) { Show-Status; return }

    if ($Purge) {
        Write-LogWarn "Iniciando purga total..."
        Stop-Service W3SVC, Apache*, nginx -Force -ErrorAction SilentlyContinue
        sc.exe delete nginx | Out-Null
        choco uninstall nginx apache-httpd -y | Out-Null
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart | Out-Null
        Write-LogSuccess "Sistema limpio."
        return
    }

    if ($Service -ne "") {
        if ($ListVersions) {
            Write-LogInfo "Versiones para ${Service}:"
            Get-DynamicVersions -Service $Service | ForEach-Object { Write-Host " - $_" }
            return
        }
        if ($Port -eq 0) { Write-LogError "Puerto requerido."; return }
        if ($ServiceVersion) { $Ver = $ServiceVersion } else { $Ver = Get-DynamicVersions -Service $Service | Select -First 1 }
        try { Install-WebServer -Service $Service -Port $Port -Version $Ver } catch { Write-LogError $_.Exception.Message }
        return
    }

    # Modo Interactivo
    while ($true) {
        # Clear-Host # Comentado para visualización en chat
        Write-Host "`n=== SISTEMA DE APROVISIONAMIENTO HTTP (Práctica 6) ===" -ForegroundColor Cyan
        Write-Host "1) IIS`n2) Apache`n3) Nginx`n4) Estado`n5) Purgar`nq) Salir"
        $choice = Read-Host "Seleccione"
        switch ($choice) {
            "1" { Install-WebServer -Service "iis" -Port (Request-ValidPort) -Version "10.0" }
            "2" {
                $v = Get-DynamicVersions -Service "apache"
                Write-Host "Seleccione version: `n1) $($v[0])`n2) $($v[1])"
                $vs = Read-Host
                if ($vs -eq "2") { $ver = $v[1] } else { $ver = $v[0] }
                Install-WebServer -Service "apache" -Port (Request-ValidPort) -Version $ver
            }
            "3" {
                $v = Get-DynamicVersions -Service "nginx"
                Write-Host "Seleccione version: `n1) $($v[0])`n2) $($v[1])"
                $vs = Read-Host
                if ($vs -eq "2") { $ver = $v[1] } else { $ver = $v[0] }
                Install-WebServer -Service "nginx" -Port (Request-ValidPort) -Version $ver
            }
            "4" { Show-Status }
            "5" { Write-LogWarn "Use --purge para limpiar el sistema." }
            "q" { return }
        }
    }
}

Main

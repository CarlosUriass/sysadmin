# Requires -RunAsAdministrator
#Requires -Version 5.1
param(
    [string]$Service = "",
    [int]$Port = 0,
    [string]$ServiceVersion = "",
    [switch]$ListVersions,
    [switch]$Status,
    [switch]$Purge,
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Write-LogInfo    ([string]$m) { Write-Host "[INFO] $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Cyan   }
function Write-LogSuccess ([string]$m) { Write-Host "[OK]   $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Green  }
function Write-LogWarn    ([string]$m) { Write-Host "[WARN] $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Yellow }
function Write-LogError   ([string]$m) { Write-Host "[FAIL] $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Red   }

function Test-PortInUse ([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}
function Get-NearbyAvailablePorts ([int]$Port) {
    $s = @()
    for ($i = $Port + 1; $i -le [Math]::Min($Port + 20, 65535); $i++) {
        if (-not (Test-PortInUse $i)) { $s += $i; if ($s.Count -ge 3) { break } }
    }
    return $s
}
function Ensure-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-LogWarn "Instalando Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
    }
}
function Generate-IndexHtml {
    param([string]$Path, [string]$Svc, [string]$Ver, [int]$Port)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $html = "<html><body><h1>Servidor: $Svc - Version: $Ver - Puerto: $Port</h1><p>Aprovisionamiento Automatizado - Windows (Practica 6)</p><p>Fecha: $time</p></body></html>"
    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($false))
    Write-LogSuccess "Pagina index.html generada en $Path"
}

function Ensure-ApacheExtracted {
    $dest = "C:\tools\Apache24"
    if (Test-Path "$dest\bin\httpd.exe") { Write-LogInfo "Apache ya extraido en $dest"; return $dest }
    $chocoTools = "$env:ALLUSERSPROFILE\chocolatey\lib\apache-httpd\tools"
    $zip = Get-ChildItem -Path $chocoTools -Filter "httpd-*-x64-*.zip" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $zip) { $zip = Get-ChildItem -Path $chocoTools -Filter "httpd-*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $zip) { Write-LogError "No se encontro el ZIP de Apache en $chocoTools"; return $null }
    Write-LogInfo "Extrayendo $($zip.Name) -> C:\tools ..."
    New-Item -ItemType Directory -Path "C:\tools" -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try { [System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, "C:\tools") } catch { Write-LogWarn "Extraccion: $_" }
    if (Test-Path "$dest\bin\httpd.exe") { Write-LogSuccess "Apache extraido en $dest"; return $dest }
    $found = Get-ChildItem -Path "C:\tools" -Recurse -Filter "httpd.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return Split-Path $found.DirectoryName -Parent }
    Write-LogError "httpd.exe no encontrado tras extraccion."
    return $null
}

function Ensure-NginxExtracted {
    $dest = "C:\tools\nginx"
    if (Test-Path "$dest\nginx.exe") { Write-LogInfo "Nginx ya extraido en $dest"; return $dest }
    $chocoTools = "$env:ALLUSERSPROFILE\chocolatey\lib\nginx\tools"
    $zip = Get-ChildItem -Path $chocoTools -Filter "nginx-*.zip" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $zip) { Write-LogError "No se encontro el ZIP de Nginx en $chocoTools"; return $null }
    Write-LogInfo "Extrayendo $($zip.Name) -> C:\tools\nginx_tmp ..."
    $tmp = "C:\tools\nginx_tmp"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try { [System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $tmp) } catch { Write-LogWarn "Extraccion: $_" }
    $extracted = Get-ChildItem -Path $tmp -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^nginx" } | Select-Object -First 1
    if ($extracted -and (Test-Path "$($extracted.FullName)\nginx.exe")) {
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        Move-Item $extracted.FullName $dest
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        Write-LogSuccess "Nginx extraido en $dest"
        return $dest
    }
    $found = Get-ChildItem -Path $tmp -Recurse -Filter "nginx.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.DirectoryName }
    Write-LogError "nginx.exe no encontrado tras extraccion."
    return $null
}

function Set-ServiceUserAndPermissions {
    param([string]$ServiceName, [string]$Path)
    $user = "svc_$ServiceName"
    Write-LogInfo "Configurando usuario $user para $Path ..."
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        $pass = ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force
        New-LocalUser -Name $user -Password $pass -Description "Service user for $ServiceName" | Out-Null
    }
    if (Test-Path $Path) {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $true)
        $rules = $acl.Access | Where-Object { $_.IdentityReference -match "BUILTIN\\Users$" -and $_.IsInherited -eq $false }
        foreach ($r in $rules) { $acl.RemoveAccessRule($r) | Out-Null }
        foreach ($id in @($user, "IUSR", "IIS_IUSRS")) {
            try {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
                $acl.SetAccessRule($rule)
            } catch { Write-LogWarn "ACL $id : $_" }
        }
        Set-Acl $Path $acl
        Write-LogInfo "Permisos ACL aplicados en $Path"
    }
}

function Stop-IISServices {
    Write-LogInfo "Deteniendo WAS y W3SVC..."
    Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
    Stop-Service WAS   -Force -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        $w3  = (Get-Service W3SVC -ErrorAction SilentlyContinue).Status
        $was = (Get-Service WAS   -ErrorAction SilentlyContinue).Status
        if ($w3 -ne 'Running' -and $was -ne 'Running') { break }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds 1
}
function Start-IISServices {
    Start-Service WAS   -ErrorAction SilentlyContinue; Start-Sleep 1
    Start-Service W3SVC -ErrorAction SilentlyContinue; Start-Sleep 3
}

function Apply-IISHardening ([int]$Port) {
    Write-LogInfo "Aplicando Hardening a IIS..."
    Import-Module WebAdministration -ErrorAction Stop
    $configPath = "$env:SystemRoot\system32\inetsrv\config\applicationHost.config"
    Stop-IISServices
    try {
        [xml]$config = Get-Content $configPath -Encoding UTF8
        $site = $config.configuration.'system.applicationHost'.sites.site | Where-Object { $_.name -eq "Default Web Site" }
        if ($site) {
            $site.bindings.RemoveAll()
            $b = $config.CreateElement("binding")
            $b.SetAttribute("protocol", "http")
            $b.SetAttribute("bindingInformation", "*:${Port}:")
            $site.bindings.AppendChild($b) | Out-Null
            $config.Save($configPath)
            Write-LogInfo "Binding IIS -> puerto $Port"
        }
    } catch { Write-LogWarn "applicationHost.config: $_" }
    Start-IISServices
    $webDir = "C:\inetpub\wwwroot"
    if (-not (Test-Path $webDir)) { New-Item -ItemType Directory -Path $webDir -Force | Out-Null }
    $wc = '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><httpProtocol><customHeaders><clear /><remove name="X-Powered-By" /><add name="X-Frame-Options" value="SAMEORIGIN" /><add name="X-Content-Type-Options" value="nosniff" /></customHeaders></httpProtocol><security><requestFiltering removeServerHeader="true"><verbs allowUnlisted="true"><clear /><add verb="TRACE" allowed="false" /><add verb="TRACK" allowed="false" /></verbs></requestFiltering></security></system.webServer></configuration>'
    [System.IO.File]::WriteAllText("$webDir\web.config", $wc, [System.Text.UTF8Encoding]::new($false))
    Write-LogInfo "web.config escrito."
}

function Set-FirewallRule ([int]$Port, [string]$Svc) {
    $name = "HTTP-Allow-$Svc-$Port"
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    }
    Write-LogInfo "Firewall: puerto $Port habilitado ($Svc)"
}

function Get-DynamicVersions ([string]$Service) {
    Ensure-Chocolatey
    $versions = @()
    switch ($Service.ToLower()) {
        "iis" { return @("10.0") }
        "apache" {
            try { $out = choco search apache-httpd --exact --all-versions 2>$null | Select-String "apache-httpd\s+\d"; foreach ($l in $out) { $versions += ($l.ToString().Trim() -split '\s+')[1] } } catch {}
            if ($versions.Count -eq 0) { $versions = @("2.4.58","2.4.55","2.4.54") }
        }
        "nginx" {
            try { $out = choco search nginx --exact --all-versions 2>$null | Select-String "^nginx\s+\d"; foreach ($l in $out) { $versions += ($l.ToString().Trim() -split '\s+')[1] } } catch {}
            if ($versions.Count -eq 0) { $versions = @("1.29.6","1.27.4","1.26.3") }
        }
    }
    return $versions | Select-Object -First 5
}

function Install-IIS ([int]$Port, [string]$Version) {
    $features = @("IIS-WebServerRole","IIS-WebServer","IIS-CommonHttpFeatures","IIS-DefaultDocument","IIS-StaticContent","IIS-RequestFiltering","IIS-ManagementConsole")
    foreach ($f in $features) {
        if ((Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State -ne "Enabled") {
            Write-LogInfo "Habilitando feature: $f"
            Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null
        }
    }
    Start-Service WAS   -ErrorAction SilentlyContinue; Start-Sleep 1
    Start-Service W3SVC -ErrorAction SilentlyContinue; Start-Sleep 4
    Apply-IISHardening -Port $Port
    Generate-IndexHtml -Path "C:\inetpub\wwwroot\index.html" -Svc "IIS" -Ver $Version -Port $Port
    Set-ServiceUserAndPermissions -ServiceName "iis" -Path "C:\inetpub\wwwroot"
    return $true
}

function Install-ApacheHTTP ([int]$Port, [string]$Version) {
    Ensure-Chocolatey
    Write-LogInfo "Descargando Apache $Version via Chocolatey..."
    choco install apache-httpd --version=$Version -y --no-progress --force
    $apachePath = Ensure-ApacheExtracted
    if (-not $apachePath) { return $false }
    $conf = "$apachePath\conf\httpd.conf"
    if (-not (Test-Path $conf)) { Write-LogError "httpd.conf no encontrado en $conf"; return $false }
    Write-LogInfo "Configurando $conf ..."
    $c = Get-Content $conf -Raw
    $c = $c -replace '(?m)^Listen\s+80\b',           "Listen $Port"
    $c = $c -replace '(?m)^#?ServerTokens\s+\w+',    "ServerTokens Prod"
    $c = $c -replace '(?m)^#?ServerSignature\s+\w+', "ServerSignature Off"
    $c = $c -replace '#LoadModule headers_module',    'LoadModule headers_module'
    if ($c -notmatch "X-Frame-Options") {
        $c += "`r`nHeader always set X-Frame-Options SAMEORIGIN"
        $c += "`r`nHeader always set X-Content-Type-Options nosniff"
    }
    if ($c -notmatch "LimitExcept") {
        $fwd = $apachePath -replace '\\','/'
        $c += "`r`n<Directory `"$fwd/htdocs`">`r`n    <LimitExcept GET POST>`r`n        Deny from all`r`n    </LimitExcept>`r`n</Directory>"
    }
    [System.IO.File]::WriteAllText($conf, $c, [System.Text.UTF8Encoding]::new($false))
    Set-ServiceUserAndPermissions -ServiceName "apache" -Path "$apachePath\htdocs"
    Generate-IndexHtml -Path "$apachePath\htdocs\index.html" -Svc "Apache" -Ver $Version -Port $Port
    $httpd = "$apachePath\bin\httpd.exe"
    if (-not (Get-Service "Apache*" -ErrorAction SilentlyContinue)) {
        Write-LogInfo "Registrando servicio Apache..."
        & $httpd -k install 2>&1 | Out-Null
    }
    Write-LogInfo "Iniciando Apache..."
    & $httpd -k restart 2>&1 | Out-Null
    Start-Sleep 2
    if (Test-PortInUse -Port $Port) { Write-LogSuccess "Apache escuchando en puerto $Port" }
    else { Write-LogWarn "Apache no responde en $Port - revisa $apachePath\logs\error.log" }
    return $true
}

function Install-NginxHTTP ([int]$Port, [string]$Version) {
    Ensure-Chocolatey
    Write-LogInfo "Descargando Nginx $Version via Chocolatey..."
    choco install nginx --version=$Version -y --no-progress --force
    $nginxPath = Ensure-NginxExtracted
    if (-not $nginxPath) { return $false }
    $conf = "$nginxPath\conf\nginx.conf"
    if (-not (Test-Path $conf)) { Write-LogError "nginx.conf no encontrado en $conf"; return $false }
    Write-LogInfo "Configurando $conf ..."
    $c = Get-Content $conf -Raw
    $c = $c -replace 'listen\s+80;',              "listen $Port;"
    $c = $c -replace 'listen\s+\[::]:80;',        "listen [::]:$Port;"
    $c = $c -replace '#?\s*server_tokens\s+\w+;', "server_tokens off;"
    if ($c -notmatch "X-Frame-Options") {
        $c = $c -replace '(server\s*\{)', ('$1' + "`n        add_header X-Frame-Options SAMEORIGIN;`n        add_header X-Content-Type-Options nosniff;")
    }
    [System.IO.File]::WriteAllText($conf, $c, [System.Text.UTF8Encoding]::new($false))
    Set-ServiceUserAndPermissions -ServiceName "nginx" -Path "$nginxPath\html"
    Generate-IndexHtml -Path "$nginxPath\html\index.html" -Svc "Nginx" -Ver $Version -Port $Port
    $nginxExe = "$nginxPath\nginx.exe"
    if (-not (Get-Service nginx -ErrorAction SilentlyContinue)) {
        Write-LogInfo "Registrando servicio nginx..."
        if (Get-Command nssm -ErrorAction SilentlyContinue) {
            nssm install nginx $nginxExe | Out-Null
            nssm set nginx AppDirectory $nginxPath | Out-Null
        } else {
            New-Service -Name "nginx" -BinaryPathName "`"$nginxExe`"" -StartupType Automatic | Out-Null
        }
    }
    Write-LogInfo "Iniciando Nginx..."
    Push-Location $nginxPath
    Start-Process -FilePath $nginxExe -ArgumentList "-s","stop" -NoNewWindow -Wait -ErrorAction SilentlyContinue
    Start-Process -FilePath $nginxExe -NoNewWindow
    Pop-Location
    Start-Sleep 2
    if (Test-PortInUse -Port $Port) { Write-LogSuccess "Nginx escuchando en puerto $Port" }
    else { Write-LogWarn "Nginx no responde en $Port - revisa $nginxPath\logs\error.log" }
    return $true
}

function Install-WebServer ([string]$Service, [int]$Port, [string]$Version) {
    Write-LogInfo "Iniciando despliegue de $Service ($Version) en puerto $Port..."
    if (Test-PortInUse -Port $Port) {
        Write-LogError "Puerto $Port ocupado. Recomendados: $((Get-NearbyAvailablePorts $Port) -join ', ')"
        return
    }
    $ok = $false
    switch ($Service.ToLower()) {
        "iis"    { $ok = Install-IIS        -Port $Port -Version $Version }
        "apache" { $ok = Install-ApacheHTTP -Port $Port -Version $Version }
        "nginx"  { $ok = Install-NginxHTTP  -Port $Port -Version $Version }
        default  { Write-LogError "Servicio no soportado: $Service"; return }
    }
    if ($ok) { Set-FirewallRule -Port $Port -Svc $Service; Write-LogSuccess "Servicio $Service desplegado en puerto $Port." }
    else { Write-LogError "Despliegue de $Service fallido." }
}

function Show-Status {
    Write-Host "`n--- ESTADO DE SERVICIOS ---" -ForegroundColor White
    Get-Service -Name W3SVC,WAS,Apache*,nginx -ErrorAction SilentlyContinue | Select-Object Name,Status | Format-Table -AutoSize
    Write-Host "`n--- PUERTOS HTTP ACTIVOS ---" -ForegroundColor White
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in (80,443,3001,3002,3003,3004,3005,3006,3007,3008,3009,3010) } | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize
}

function Invoke-Purge {
    Write-LogWarn "Iniciando purga total..."
    Stop-IISServices
    Stop-Service Apache*,nginx -Force -ErrorAction SilentlyContinue
    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 2
    sc.exe delete nginx  2>$null | Out-Null
    sc.exe delete Apache 2>$null | Out-Null
    Ensure-Chocolatey
    choco uninstall nginx apache-httpd -y --remove-dependencies 2>&1 | Out-Null
    try { Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}
    Remove-Item "C:\tools\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\tools\nginx"    -Recurse -Force -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName "HTTP-Allow-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-LogSuccess "Purga completada."
}

function Request-ValidPort {
    while ($true) {
        Write-Host "Ingrese puerto (80 o 1024-65535): " -ForegroundColor Cyan -NoNewline
        $pStr = Read-Host
        $p = 0
        if ([int]::TryParse($pStr, [ref]$p) -and ($p -eq 80 -or ($p -ge 1024 -and $p -le 65535))) {
            if (-not (Test-PortInUse -Port $p)) { return $p }
            Write-LogError "Puerto $p ocupado. Disponibles: $((Get-NearbyAvailablePorts $p) -join ', ')"
        } else { Write-LogWarn "Puerto invalido." }
    }
}

function Select-Version ([string]$Service) {
    $v = Get-DynamicVersions -Service $Service
    Write-Host "Seleccione version:" -ForegroundColor Cyan
    for ($i = 0; $i -lt [Math]::Min($v.Count, 5); $i++) { Write-Host "  $($i+1)) $($v[$i])" }
    Write-Host "  (Enter para la mas reciente)" -ForegroundColor Gray
    $sel = Read-Host "Opcion"
    $idx = 0
    if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $v.Count) { return $v[$idx - 1] }
    return $v[0]
}

function Main {
    if ($Help) { Write-Host "Uso: .\http_deploy.ps1 [-Service iis|apache|nginx] [-Port N] [-ServiceVersion V] [-Status] [-Purge]"; return }
    if ($Status) { Show-Status; return }
    if ($Purge)  { Invoke-Purge; return }
    if ($Service -ne "") {
        if ($ListVersions) { Get-DynamicVersions -Service $Service | ForEach-Object { Write-Host "  - $_" }; return }
        if ($Port -eq 0) { Write-LogError "Especifica -Port <num>"; return }
        $ver = if ($ServiceVersion) { $ServiceVersion } else { (Get-DynamicVersions -Service $Service)[0] }
        Install-WebServer -Service $Service -Port $Port -Version $ver
        return
    }
    while ($true) {
        Write-Host "`n=== SISTEMA DE APROVISIONAMIENTO HTTP (Practica 6) ===" -ForegroundColor Cyan
        Write-Host "  1) IIS`n  2) Apache`n  3) Nginx`n  4) Estado`n  5) Purgar`n  q) Salir"
        switch ((Read-Host "Seleccione").ToLower()) {
            "1" { Install-WebServer -Service "iis"    -Port (Request-ValidPort) -Version "10.0" }
            "2" { $ver = Select-Version "apache"; Install-WebServer -Service "apache" -Port (Request-ValidPort) -Version $ver }
            "3" { $ver = Select-Version "nginx";  Install-WebServer -Service "nginx"  -Port (Request-ValidPort) -Version $ver }
            "4" { Show-Status }
            "5" { Invoke-Purge }
            "q" { return }
            default { Write-LogWarn "Opcion no valida." }
        }
    }
}
Main
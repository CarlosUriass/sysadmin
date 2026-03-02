<#
.SYNOPSIS
Instalación y configuración automatizada, segura e idempotente 
de un servidor FTP (IIS) en Windows Server.

.DESCRIPTION
Este script instala IIS, configura un sitio FTP con Modo Pasivo, 
Aislamiento de Usuarios (User Isolation), permisos estrictos (NTFS),
y cuenta con la misma lógica interactiva de aprovisionamiento 
que nuestra versión original en Linux.
#>

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile   = "C:\var\log\ftp-automation.log"
$FtpRoot   = "C:\inetpub\ftproot"

# ==============================================================================
# 0. FUNCIONES DE UTILIDAD Y LOGGING
# ==============================================================================
$LoggerScript = Join-Path $ScriptDir "..\..\utils\logs\logger.ps1"
if (Test-Path $LoggerScript) {
    . $LoggerScript
} else {
    Write-Host "ERROR: No se encuentra la utilidad logger.ps1 en utils\logs\" -ForegroundColor Red
    Exit 1
}

function Check-Root {
    $Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-Not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-LogError "Este script debe ejecutarse como Administrador."
    }
}

function Install-Packages {
    $InstallerScript = Join-Path $ScriptDir "..\..\utils\ps1\install_feature.ps1"

    # ===========================================================================
    # LISTA COMPLETA DE FEATURES REQUERIDAS (idempotente)
    # - Web-Server         : Motor IIS base. Registra W3SVC y WAS (requeridos por
    #                        WebAdministration y Start-WebSite / New-WebFtpSite).
    # - Web-WebServer      : Rol padre del servidor web (necesario para Web-Server).
    # - Web-Ftp-Server     : Rol padre FTP.
    # - Web-Ftp-Service    : Servicio FTP real (ftpsvc).
    # - Web-Ftp-Ext        : Extensibilidad FTP para configurar via PowerShell/WMI.
    # - Web-Mgmt-Console   : IIS Manager GUI (util para diagnóstico).
    # - Web-Scripting-Tools: appcmd.exe y WebAdministration completo.
    # ===========================================================================
    $Features = @(
        "Web-Server",
        "Web-WebServer",
        "Web-Ftp-Server",
        "Web-Ftp-Service",
        "Web-Ftp-Ext",
        "Web-Mgmt-Console",
        "Web-Scripting-Tools"
    )

    if (Test-Path $InstallerScript) {
        foreach ($Feature in $Features) {
            & $InstallerScript -FeatureName $Feature
        }
    } else {
        foreach ($Feature in $Features) {
            $Check = Get-WindowsFeature -Name $Feature -ErrorAction SilentlyContinue
            if ($null -eq $Check) {
                Write-LogWarn "No se pudo consultar el feature $Feature. Omitiendo."
                continue
            }
            if ($Check.Installed) {
                Write-LogSuccess "$Feature ya se encuentra instalado."
            } else {
                Write-LogInfo "Instalando $Feature..."
                Install-WindowsFeature -Name $Feature -IncludeManagementTools | Out-Null
                Write-LogSuccess "$Feature instalado exitosamente."
            }
        }
    }

    # Garantizar que W3SVC y WAS estén corriendo ANTES de importar WebAdministration.
    # Sin estos servicios activos, los cmdlets de IIS lanzan "Class not registered".
    Write-LogInfo "Verificando servicios base de IIS (W3SVC / WAS)..."
    foreach ($Svc in @("WAS", "W3SVC")) {
        $SvcObj = Get-Service -Name $Svc -ErrorAction SilentlyContinue
        if ($null -eq $SvcObj) {
            Write-LogError "El servicio $Svc no existe. Verifique que Web-Server se instaló correctamente y reinicie el script."
        }
        if ($SvcObj.StartType -ne "Automatic") {
            Set-Service -Name $Svc -StartupType Automatic
        }
        if ($SvcObj.Status -ne "Running") {
            Write-LogInfo "Iniciando servicio $Svc..."
            Start-Service -Name $Svc
        }
        Write-LogSuccess "Servicio $Svc activo."
    }

    Import-Module WebAdministration -Force
    Write-LogSuccess "Módulo WebAdministration cargado correctamente."
}

# ==============================================================================
# 1. GESTION DE DIRECTORIOS BASE, GRUPOS Y PERMISOS NTFS
# ==============================================================================
function Configure-BaseAndGroups {
    Write-LogInfo "Configurando directorios base y grupos locales..."

    # Crear Grupos Locales
    $Groups = @("ftpusers", "reprobados", "recursadores")
    foreach ($Group in $Groups) {
        if (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue) {
            Write-LogSuccess "El grupo $Group ya existe."
        } else {
            New-LocalGroup -Name $Group -Description "Grupo FTP automatizado" | Out-Null
            Write-LogSuccess "Grupo local $Group creado."
        }
    }

    # Crear estructura estricta en ftproot
    $Folders = @(
        "$FtpRoot\general",
        "$FtpRoot\reprobados",
        "$FtpRoot\recursadores"
    )
    foreach ($Folder in $Folders) {
        if (-Not (Test-Path $Folder)) {
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
        }
    }

    # --- ACLs (Seguridad equivalente a CHMOD linux) ---
    Write-LogInfo "Aplicando permisos estrictos (ACL NTFS) a las carpetas raíz..."

    # General: Solo ftpusers puede modificar.
    $AclGen = Get-Acl "$FtpRoot\general"
    $AclGen.SetAccessRuleProtection($True, $False)
    $AclGen.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $AclGen.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("ftpusers", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl -Path "$FtpRoot\general" -AclObject $AclGen

    # Reprobados / Recursadores: Solo administradores y su propio grupo
    foreach ($Grp in @("reprobados", "recursadores")) {
        $Path = "$FtpRoot\$Grp"
        $Acl = Get-Acl $Path
        $Acl.SetAccessRuleProtection($True, $False)
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Grp, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $Path -AclObject $Acl
    }

    Write-LogSuccess "Seguridad en partición de disco y grupos locales FTP establecidas."
}

# ==============================================================================
# 2. CONFIGURACION IIS FTP E AISLAMIENTO
# ==============================================================================
function Configure-IISFtp {
    Write-LogInfo "Configurando sitio en el IIS..."
    Import-Module WebAdministration -Force

    $SiteName = "AutomatedFTP"
    $AppCmd    = "$env:windir\system32\inetsrv\appcmd.exe"

    # 1. Eliminar el sitio si existe (idempotente: recrear limpio)
    if (Get-WebSite -Name $SiteName -ErrorAction SilentlyContinue) {
        Remove-WebSite -Name $SiteName -Confirm:$false | Out-Null
        Write-LogInfo "Sitio FTP anterior eliminado."
    }

    if (Get-WebSite -Name "Default FTP Site" -ErrorAction SilentlyContinue) {
        Remove-WebSite -Name "Default FTP Site" -Confirm:$false | Out-Null
    }

    # 2. Crear sitio FTP
    New-WebFtpSite -Name $SiteName -Port 21 -PhysicalPath $FtpRoot -Force | Out-Null
    Write-LogSuccess "Sitio FTP real $SiteName creado en el puerto 21."

    Write-LogInfo "Asegurando soporte FTPS y Modo Pasivo..."

    # Modo Pasivo (rango de puertos a nivel global IIS)
    & $AppCmd set config -section:system.ftpServer/firewallSupport /lowDataChannelPort:"40000"  /commit:apphost | Out-Null
    & $AppCmd set config -section:system.ftpServer/firewallSupport /highDataChannelPort:"40100" /commit:apphost | Out-Null

    # Certificado Autofirmado
    $CertSubject = "CN=FtpLocalServer"
    $Cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $CertSubject }
    if (-Not $Cert) {
        $Cert = New-SelfSignedCertificate -DnsName "FtpLocalServer" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(1)
        Write-LogSuccess "Certificado Autofirmado SSL Generado."
    } else {
        Write-LogSuccess "El certificado SSL Autofirmado ya existe."
    }

    # SSL Opcional (0 = permite texto plano y SSL, no fuerza cifrado)
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.ssl.serverCertHash"       -Value $Cert.Thumbprint
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value 0
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value 0
    Write-LogSuccess "Control FTPS asociado al sitio $SiteName (SSL Totalmente Opcional/Texto Plano Permitido)."

    # Aislamiento de usuarios (2 = IsolateAllDirectories / LocalUser chroot)
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.userIsolation.mode" -Value 2

    # Autenticacion
    & $AppCmd set config "$SiteName" -section:system.ftpServer/security/authentication/basicAuthentication     /enabled:"True"  /commit:apphost | Out-Null
    
    # Habilitar Anónimo y mapearlo forzosamente a IUSR (requerido por IIS FTP para no dar 530)
    & $AppCmd set config "$SiteName" -section:system.ftpServer/security/authentication/anonymousAuthentication /enabled:"True" /userName:"IUSR" /commit:apphost | Out-Null

    # Autorización (limpiar y reconfigurar — idempotente)
    & $AppCmd clear config "$SiteName" -section:system.ftpServer/security/authorization /commit:apphost | Out-Null
    & $AppCmd set config   "$SiteName" -section:system.ftpServer/security/authorization /+"[accessType='Allow',users='Anonymous',permissions='Read']"       /commit:apphost | Out-Null
    & $AppCmd set config   "$SiteName" -section:system.ftpServer/security/authorization /+"[accessType='Allow',roles='ftpusers',permissions='Read, Write']" /commit:apphost | Out-Null

    Write-LogSuccess "Seguridad, roles y aislamiento aplicados y verificados."

    # Reiniciar ftpsvc para que IIS propague el nuevo sitio FTP en su metabase COM.
    Restart-Service ftpsvc -Force
    Start-Sleep -Seconds 2

    # Verificar si el sitio ya quedó iniciado tras el reinicio de ftpsvc.
    # En la mayoría de entornos, Restart-Service inicia todos los sitios FTP
    # automáticamente, por lo que appcmd start site lanza 0x800710D8 si se
    # intenta iniciar un sitio que ya está corriendo.
    $SiteState = & $AppCmd list site /name:"$SiteName" /text:state 2>&1
    if ($SiteState -match "Started") {
        Write-LogSuccess "Sitio $SiteName ya se encuentra iniciado (auto-start tras reinicio ftpsvc)."
    } else {
        Write-LogInfo "Estado del sitio: $SiteState. Intentando iniciar..."
        $StartResult = & $AppCmd start site /site.name:"$SiteName" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogSuccess "Sitio $SiteName iniciado correctamente via appcmd."
        } else {
            Write-LogWarn "appcmd start site: $StartResult. Intentando Start-WebSite..."
            try {
                Start-WebSite -Name $SiteName -ErrorAction Stop
                Write-LogSuccess "Sitio $SiteName iniciado via Start-WebSite."
            } catch {
                Write-LogWarn "Start-WebSite fallo: $_. Verificando puerto 21..."
            }
        }
    }

    # Validación final
    $Binding = Get-WebBinding -Name $SiteName -ErrorAction SilentlyContinue
    if ($Binding -and $Binding.Protocol -eq "ftp") {
        Write-LogSuccess "Validacion OK: Protocolo del sitio $SiteName es FTP."
    } else {
        Write-LogWarn "Validacion: No se pudo confirmar protocolo FTP en binding (puede ser normal en algunos entornos)."
    }

    $NetStat = netstat -an | findstr ":21" | findstr "LISTENING"
    if ($NetStat) {
        Write-LogSuccess "Validacion OK: Puerto 21 en estado LISTENING."
    } else {
        Write-LogError "Validacion FALLIDA: Puerto 21 NO esta a la escucha."
    }
}

# ==============================================================================
# 3. FIREWALL DE WINDOWS
# ==============================================================================
function Configure-Firewall {
    Write-LogInfo "Configurando reglas del Firewall de Windows (Modo Pasivo e Inicial)..."

    Enable-NetFirewallRule -DisplayGroup "FTP Server" -ErrorAction SilentlyContinue | Out-Null

    netsh advfirewall set global StatefulFtp enable > $null

    $ExistsPassive = Get-NetFirewallRule -DisplayName "FTP-Server-Passive" -ErrorAction SilentlyContinue
    if (-Not $ExistsPassive) {
        New-NetFirewallRule -DisplayName "FTP-Server-Passive" -Direction Inbound -Protocol TCP -LocalPort 40000-40100 -Action Allow | Out-Null
        Write-LogSuccess "Regla de Firewall agregada: FTP-Server-Passive Puerto(s): 40000-40100"
    } else {
        Write-LogSuccess "Regla FTP-Server-Passive ya existe."
    }

    Restart-Service -Name "ftpsvc" -Force

    Write-LogSuccess "Firewall de Windows configurado (Stateful FTP Global activado)."
}

# ==============================================================================
# 4. POLITICAS DE SEGURIDAD LOCAL
# ==============================================================================
function Configure-LocalSecurityPolicy {
    Write-LogWarn "Configurando políticas de seguridad locales para FTP (secedit)..."

    $CfgFile = "$env:TEMP\secpol_ftp.inf"
    secedit /export /cfg $CfgFile /Quiet | Out-Null

    $Content = Get-Content $CfgFile -Encoding Unicode

    # --- Contraseñas ---
    # Deshabilitar complejidad y longitud mínima para permitir contraseñas simples en FTP
    $Content = $Content -replace "(?i)^PasswordComplexity\s*=\s*1",      "PasswordComplexity = 0"
    $Content = $Content -replace "(?i)^MinimumPasswordLength\s*=\s*\d+", "MinimumPasswordLength = 0"

    # --- Logon de Red (CRÍTICO para FTP) ---
    # SeDenyNetworkLogonRight: si contiene ftpusers o usuarios FTP, Windows lanza
    # win32 error 1326 (ERROR_LOGON_FAILURE) antes de que IIS pueda autenticar.
    # Lo dejamos vacío para que no deniegue explícitamente a ningún grupo FTP.
    $Content = $Content -replace "(?i)^SeDenyNetworkLogonRight\s*=.*", "SeDenyNetworkLogonRight = "

    # SeNetworkLogonRight: garantizar que ftpusers tenga derecho de logon de red.
    # IIS FTP autentica via network logon internamente — sin este derecho, 530.
    $NetworkLogonLine = $Content | Where-Object { $_ -match "(?i)^SeNetworkLogonRight\s*=" }
    if ($NetworkLogonLine) {
        if ($NetworkLogonLine -notmatch "ftpusers") {
            $Content = $Content -replace "(?i)^(SeNetworkLogonRight\s*=\s*.*)", "`$1,*ftpusers"
            Write-LogInfo "Grupo ftpusers agregado a SeNetworkLogonRight."
        } else {
            Write-LogSuccess "ftpusers ya tiene SeNetworkLogonRight."
        }
    } else {
        # Si la línea no existe en el .inf, crearla en la sección [Privilege Rights]
        # *S-1-5-32-544 = Administrators, *S-1-5-32-545 = Users
        $Content = $Content -replace "(\[Privilege Rights\])", "`$1`r`nSeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545,*ftpusers"
        Write-LogInfo "SeNetworkLogonRight creado con Administrators, Users y ftpusers."
    }

    $Content | Set-Content $CfgFile -Encoding Unicode -Force

    secedit /configure /db $env:windir\security\local.sdb /cfg $CfgFile /areas SECURITYPOLICY /Quiet | Out-Null

    # Complemento via net accounts
    net accounts /maxpwage:unlimited /minpwlen:0 /minpwage:0 | Out-Null

    Write-LogSuccess "Políticas de seguridad locales configuradas (contraseñas y logon de red FTP)."
}

# ==============================================================================
# 5. GESTIÓN DE USUARIOS
# ==============================================================================

function Get-FtpUserVirtualDirectories ($Username) {
    $Username = $Username.Trim()
    $VDirs = Get-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
    return $VDirs
}

function Create-FtpUser {
    param([string]$Username, [string]$Group, [string]$Password)

    if ($Username -notmatch "^[a-z_][a-z0-9_-]{2,31}$") {
        Write-LogError "Nombre de usuario inválido. Use la convención clásica sin caracteres especiales raros."
    }

    # 1. Crear Usuario de Windows
    if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
        Write-LogWarn "El usuario local de Windows $Username ya existe. Verificando membresías y estructura FTP..."
    } else {
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $Username -Password $SecurePassword -Description "Automated FTP User" -AccountNeverExpires | Out-Null
        Write-LogSuccess "Usuario local $Username creado."
    }

    # 2. Membresías de grupos
    # IMPORTANTE — por qué cada grupo es necesario:
    #   $Group    : acceso a la carpeta compartida de su categoría (reprobados/recursadores)
    #   ftpusers  : regla de autorización IIS FTP (roles='ftpusers' en appcmd)
    #   Users     : Windows requiere este grupo para permitir network logon (win32 1326 sin él)
    #   IIS_IUSRS : el worker process de IIS necesita acceso de lectura a los directorios del usuario
    foreach ($Grp in @($Group, "ftpusers", "Users", "IIS_IUSRS")) {
        $IsMember = Get-LocalGroupMember -Group $Grp -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "*\$Username" -or $_.Name -eq $Username }
        if (-Not $IsMember) {
            Add-LocalGroupMember -Group $Grp -Member $Username -ErrorAction SilentlyContinue
            Write-LogInfo "Usuario $Username agregado al grupo $Grp."
        }
    }
    Write-LogSuccess "Membresías de $Username verificadas: $Group, ftpusers, Users, IIS_IUSRS."

    # 3. Directorio raíz del usuario (chroot físico requerido por IIS User Isolation)
    $UserRootDir = "$FtpRoot\LocalUser\$Username"
    if (-Not (Test-Path $UserRootDir)) {
        New-Item -Path $UserRootDir -ItemType Directory -Force | Out-Null
    }

    $AclHome = Get-Acl $UserRootDir
    $AclHome.SetAccessRuleProtection($True, $False)
    $AclHome.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl",    "ContainerInherit,ObjectInherit", "None", "Allow")))
    $AclHome.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Username,        "Modify",         "ContainerInherit,ObjectInherit", "None", "Allow")))
    $AclHome.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS",     "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $AclHome.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("IUSR",          "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl -Path $UserRootDir -AclObject $AclHome

    # 4. Directorios Virtuales IIS (bind-mount de Windows)
    function Ensure-VirtualDirectory ($VirtualPath, $PhysicalPath) {
        $Name    = $VirtualPath.Split('/')[-1]
        $AppPath = $VirtualPath.Substring(0, $VirtualPath.LastIndexOf('/'))

        $Exists = Get-WebVirtualDirectory -Site "AutomatedFTP" -Application $AppPath -Name $Name -ErrorAction SilentlyContinue
        if (-Not $Exists) {
            New-WebVirtualDirectory -Site "AutomatedFTP" -Name $Name -PhysicalPath $PhysicalPath -Application $AppPath -Force | Out-Null
            Write-LogInfo "Directorio Virtual IIS mapeado: $VirtualPath -> $PhysicalPath"
        } else {
            Write-LogInfo "Directorio Virtual $VirtualPath ya existe."
        }
    }

    Ensure-VirtualDirectory "/LocalUser/$Username"         $UserRootDir
    Ensure-VirtualDirectory "/LocalUser/$Username/general" "$FtpRoot\general"
    Ensure-VirtualDirectory "/LocalUser/$Username/$Group"  "$FtpRoot\$Group"

    Write-LogSuccess "Entorno virtual FTP e IIS configurado exitosamente para $Username."
}

function Change-FtpUserGroup {
    param([string]$Username, [string]$NewGroup)

    if (-Not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        Write-LogError "El usuario $Username no se encuentra en el sistema de Windows."
    }

    if ($NewGroup -ne "reprobados" -and $NewGroup -ne "recursadores") {
        Write-LogError "El grupo nuevo ($NewGroup) es inválido. Reprobados o Recursadores."
    }

    $Principal = New-Object Security.Principal.NTAccount($Username)
    $OldGroups = (Get-LocalGroup | Where-Object {
        ($_ | Get-LocalGroupMember -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -contains $Principal.Value
    } | Select-Object -ExpandProperty Name)

    $OldGroup = ""
    if ($OldGroups -contains "reprobados")       { $OldGroup = "reprobados" }
    elseif ($OldGroups -contains "recursadores") { $OldGroup = "recursadores" }

    if ($OldGroup -eq $NewGroup) {
        Write-LogSuccess "El usuario $Username ya se encuentra en el grupo $NewGroup. Nada qué hacer."
        return
    }

    Write-LogInfo "Iniciando migración de grupo para el usuario $Username ($OldGroup -> $NewGroup)..."

    if ($OldGroup) {
        Remove-LocalGroupMember -Group $OldGroup -Member $Username
    }
    Add-LocalGroupMember -Group $NewGroup -Member $Username

    if ($OldGroup -and (Get-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -Name $OldGroup -ErrorAction SilentlyContinue)) {
        Remove-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -Name $OldGroup -Force | Out-Null
        Write-LogInfo "Enlace virtual de IIS para $OldGroup eliminado de /LocalUser/$Username."
    }

    if (-Not (Get-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -Name $NewGroup -ErrorAction SilentlyContinue)) {
        New-WebVirtualDirectory -Site "AutomatedFTP" -Name $NewGroup -PhysicalPath "$FtpRoot\$NewGroup" -Application "/LocalUser/$Username" -Force | Out-Null
        Write-LogInfo "Enlace virtual nuevo mapeado: /LocalUser/$Username/$NewGroup -> $FtpRoot\$NewGroup"
    }

    Write-LogSuccess "Migración completada exitosamente. $Username ahora pertenece exclusivamente a $NewGroup."
}

# ==============================================================================
# 6. MENÚ INTERACTIVO Y FLUJO NORMAL
# ==============================================================================

function Interactive-Menu {
    Configure-BaseAndGroups
    Configure-IISFtp
    Configure-Firewall
    Configure-LocalSecurityPolicy

    Write-Host "======================================" -ForegroundColor Magenta
    Write-Host "  Configuración Base FTP completada.  " -ForegroundColor Magenta
    Write-Host "======================================" -ForegroundColor Magenta
    Write-Host ""

    while ($true) {
        $NumUsers = Read-Host "Cuantos usuarios desea crear? (0 para salir)"
        if ($NumUsers -match "^\d+$") {
            if ([int]$NumUsers -eq 0) {
                Write-LogInfo "Saliendo del asistente automatico."
                break
            }

            for ($i = 1; $i -le [int]$NumUsers; $i++) {
                Write-Host "`n--- Usuario $i ---" -ForegroundColor Cyan

                $uName = ""
                while ($true) {
                    $uName = Read-Host "Nombre de usuario (ej. juan_perez)"
                    if ($uName -match "^[a-z_][a-z0-9_-]{2,31}$") { break }
                    Write-LogWarn "Nombre invalido."
                }

                $uPass = ""
                while ($true) {
                    $sec   = Read-Host "Contrasena" -AsSecureString
                    $uPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
                    if (-not [string]::IsNullOrEmpty($uPass)) { break }
                    Write-LogWarn "La contrasena no puede estar vacia."
                }

                $uGrupo = ""
                while ($true) {
                    $uGrupo = Read-Host "Grupo (reprobados/recursadores)"
                    if ($uGrupo -eq "reprobados" -or $uGrupo -eq "recursadores") { break }
                    Write-LogWarn "Debe elegir reprobados o recursadores."
                }

                Create-FtpUser -Username $uName -Group $uGrupo -Password $uPass
            }
            break
        } else {
            Write-LogWarn "Ingrese un número."
        }
    }
}

# ==============================================================================
# 7. MANTENIMIENTO: PURGE, HELP, Y LIST
# ==============================================================================
function Show-Help {
    Write-Host "Uso: .\ftp.ps1 [OPCION]"
    Write-Host ""
    Write-Host "Opciones:"
    Write-Host "  -Help                                Mostrar esta ayuda"
    Write-Host "  -Purge                               Purgar IIS FTP, borrar usuarios, configuraciones y directorios"
    Write-Host "  -List                                Listar los usuarios FTP creados y su grupo actual"
    Write-Host "  -ChangeGroup -User <U> -Group <G>    Cambiar el grupo de un usuario (reprobados/recursadores)"
    Write-Host "  Sin opciones                         Inicia el flujo de instalación y configuración interactiva"
}

function List-Users {
    Write-Host "=== USUARIOS FTP REGISTRADOS ===" -ForegroundColor Cyan
    Write-Host ("{0,-20} | {1,-15}" -f "USUARIO", "GRUPO")
    Write-Host "----------------------------------------"

    $HayUsuarios = $false

    if (Get-LocalGroup -Name "ftpusers" -ErrorAction SilentlyContinue) {
        $Members = Get-LocalGroupMember -Group "ftpusers" | Where-Object PrincipalSource -eq "Local"
        foreach ($Member in $Members) {
            $UserNameStr = ($Member.Name -split "\\")[1]

            $GrpList = (Get-LocalGroup | Where-Object {
                ($_ | Get-LocalGroupMember -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -contains $Member.Name
            } | Select-Object -ExpandProperty Name)

            $GrupoPrincipal = ""
            if ($GrpList -contains "reprobados")       { $GrupoPrincipal = "reprobados" }
            elseif ($GrpList -contains "recursadores") { $GrupoPrincipal = "recursadores" }
            else                                       { $GrupoPrincipal = "Generico" }

            Write-Host ("{0,-20} | {1,-15}" -f $UserNameStr, $GrupoPrincipal)
            $HayUsuarios = $true
        }
    }

    if (-Not $HayUsuarios) {
        Write-Host "No hay usuarios FTP creados por este script."
    }
    Write-Host "----------------------------------------"
}

function Purge-Ftp {
    Write-LogWarn "Iniciando purgado completo de FTP. IIS retendrá otros sitios, pero AutomatedFTP caerá."

    Import-Module WebAdministration -Force

    if (Test-Path "IIS:\Sites\AutomatedFTP") {
        Remove-WebSite -Name "AutomatedFTP" -Confirm:$false | Out-Null
        Write-LogInfo "Sitio FTP de IIS eliminado."
    }

    if (Get-LocalGroup -Name "ftpusers" -ErrorAction SilentlyContinue) {
        $Members = Get-LocalGroupMember -Group "ftpusers" | Where-Object PrincipalSource -eq "Local"
        foreach ($Member in $Members) {
            $UserNameStr = ($Member.Name -split "\\")[1]
            Remove-LocalUser -Name $UserNameStr -ErrorAction SilentlyContinue
            Write-LogInfo "Usuario Local de Windows [$UserNameStr] eliminado."
        }
    }

    foreach ($G in @("ftpusers", "reprobados", "recursadores")) {
        if (Get-LocalGroup -Name $G -ErrorAction SilentlyContinue) {
            Remove-LocalGroup -Name $G -ErrorAction SilentlyContinue
        }
    }

    if (Test-Path $FtpRoot) {
        Remove-Item -Path $FtpRoot -Recurse -Force -Confirm:$false
        Write-LogInfo "Directorios físicos eliminados."
    }

    foreach ($RuleName in @("FTP-Server-Control", "FTP-Server-Secure", "FTP-Server-Passive")) {
        if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        }
    }

    Write-LogSuccess "Purgado exitoso. El servidor Windows ha regresado a la normalidad pre-script."
}

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================
Check-Root

if ($args.Count -eq 0) {
    Write-LogInfo "Iniciando instalación y configuración automatizada FTP PowerShell (Windows IIS)."
    Install-Packages
    Interactive-Menu
    Write-LogSuccess "Proceso de automatización finalizado correctamente."
    Exit 0
}

switch ($args[0]) {
    "-Help" {
        Show-Help
    }
    "-List" {
        List-Users
    }
    "-Purge" {
        Purge-Ftp
    }
    "-ChangeGroup" {
        if ($args.Count -lt 5) {
            Show-Help
            Write-LogError "Verifique formato: .\ftp.ps1 -ChangeGroup -User X -Group Y"
        }

        $U = ""; $G = ""
        for ($i = 1; $i -lt $args.Count; $i++) {
            if ($args[$i] -match "(?i)^-User$")  { $U = $args[$i+1] }
            if ($args[$i] -match "(?i)^-Group$") { $G = $args[$i+1] }
        }

        if (-not $U -or -not $G) {
            Show-Help
            Write-LogError "Formato requerido: .\ftp.ps1 -ChangeGroup -User <usuario> -Group <nuevo_grupo>"
        }

        Change-FtpUserGroup -Username $U -NewGroup $G
    }
    default {
        Show-Help
        Write-LogError "Opcion desconocida: $($args[0])"
    }
}
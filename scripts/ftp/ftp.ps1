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
    # Instalador robusto si existe la utilidad
    $InstallerScript = Join-Path $ScriptDir "..\..\utils\ps1\install_feature.ps1"
    # Web-Ftp-Ext es crítico para poder editar configuración interna del FTP via PowerShell (IIS Extensibility/WMI)
    $Features = @("Web-Ftp-Server", "Web-Ftp-Service", "Web-Ftp-Ext", "Web-Mgmt-Console")
    
    if (Test-Path $InstallerScript) {
        foreach ($Feature in $Features) {
            & $InstallerScript -FeatureName $Feature
        }
    } else {
        foreach ($Feature in $Features) {
            $Check = Get-WindowsFeature $Feature -ErrorAction SilentlyContinue
            if ($Check.Installed) {
                Write-LogSuccess "$Feature ya se encuentra instalado."
            } else {
                Write-LogInfo "Instalando $Feature..."
                Install-WindowsFeature -Name $Feature -IncludeManagementTools | Out-Null
                Write-LogSuccess "$Feature instalado exitosamente."
            }
        }
    }
    
    Import-Module WebAdministration
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

    # General: Solo ftpusers puede modificar. Usuarios anónimos leerán (después configurado en IIS)
    $AclGen = Get-Acl "$FtpRoot\general"
    $AclGen.SetAccessRuleProtection($True, $False) # Romper herencia
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
    Import-Module WebAdministration 

    $SiteName = "AutomatedFTP"

    # Remover el sitio por defecto si estorba
    if (Get-WebSite "Default FTP Site" -ErrorAction SilentlyContinue) {
        Remove-WebSite -Name "Default FTP Site" | Out-Null
    }

    if (Test-Path "IIS:\Sites\$SiteName") {
        Write-LogSuccess "El sitio $SiteName ya está creado en IIS."
    } else {
        # Crear sitio FTP 
        New-WebSite -Name $SiteName -PhysicalPath $FtpRoot -Port 21 -Force | Out-Null
        
        # Configurar Aislamiento (User Isolation). 
        # IsolateUsers=2 (Isolation by physical and virtual directories using user name)
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.userIsolation.mode" -Value 2

        # Configurar Inicio de sesión
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.authentication.basicAuthentication.enabled" -Value $True
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $True

        # Permisos Globales (Authorization Rules) -> Las NTFS harán el filtrado real, 
        # pero IIS Autoriza conexiones iniciales
        Add-WebConfigurationProperty -Filter "/system.ftpServer/security/authorization" -Name "." -Value @{accessType="Allow";users="*";permissions="Read,Write"} -PSPath "IIS:\Sites\$SiteName"

        Write-LogSuccess "Sitio $SiteName de IIS FTP creado con Aislamiento de Usuario."
    }

    Write-LogInfo "Asegurando soporte FTPS y Modo Pasivo..."

    # MODO PASIVO IIS (a nivel de aplicación general)
    Set-WebConfigurationProperty -Filter "/system.ftpServer/firewallSupport" -Name lowDataChannelPort -Value 40000
    Set-WebConfigurationProperty -Filter "/system.ftpServer/firewallSupport" -Name highDataChannelPort -Value 40100

    # Certificado Autofirmado
    $CertSubject = "CN=FtpLocalServer"
    $Cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $CertSubject }
    if (-Not $Cert) {
        $Cert = New-SelfSignedCertificate -DnsName "FtpLocalServer" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(1)
        Write-LogSuccess "Certificado Autofirmado SSL Generado."
    } else {
        Write-LogSuccess "El certificado SSL Autofirmado ya existe."
    }

    # Aplicarlo al binding predeterminado FTP si no está aplicado
    $Binding = Get-WebBinding -Name $SiteName -Protocol "ftp"
    if ($null -eq $Binding.BindingInformation) {
        # Asociar SSL Security Control
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.ssl.serverCertHash" -Value $Cert.Thumbprint
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslAllow"
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name "ftpServer.security.ssl.dataChannelPolicy" -Value "SslAllow"
        Write-LogSuccess "Control FTPS asociado al sitio $SiteName."
    }
    
    Restart-Service -Name "ftpsvc" -Force
}

# ==============================================================================
# 3. FIREWALL DE WINDOWS
# ==============================================================================
function Configure-Firewall {
    Write-LogInfo "Configurando reglas del Firewall de Windows (Modo Pasivo e Inicial)..."

    $Rules = @(
        @{ Name = "FTP-Server-Control"; Port = 21 },
        @{ Name = "FTP-Server-Secure"; Port = 990 },
        @{ Name = "FTP-Server-Passive"; Port = "40000-40100" }
    )

    foreach ($Rule in $Rules) {
        $Exists = Get-NetFirewallRule -DisplayName $Rule.Name -ErrorAction SilentlyContinue
        if (-Not $Exists) {
            New-NetFirewallRule -DisplayName $Rule.Name -Direction Inbound -Protocol TCP -LocalPort $Rule.Port -Action Allow | Out-Null
            Write-LogSuccess "Regla de Firewall agregada: $($Rule.Name) Puerto(s): $($Rule.Port)"
        }
    }
    
    # Habilitar inspeccion de estado FTP (Crucial para clientes externos pase Pasivo FTP libremente)
    $StatefulFTP = Get-NetFirewallRule -DisplayName "FTP-Server-Stateful" -ErrorAction SilentlyContinue
    if (-Not $StatefulFTP) {
        New-NetFirewallRule -DisplayName "FTP-Server-Stateful" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow -Service "ftpsvc" | Out-Null
        # Forzar la carga del modulo ALG si el firewall lo droppea externamente
        netsh advfirewall firewall add rule name="FTP-Internet" action=allow protocol=TCP dir=in localport=21 > $null
        Write-LogSuccess "Inspeccion de estado y acceso desde Internet para FTP habilitado."
    }

    Write-LogSuccess "Firewall de Windows configurado."
}

function Configure-LocalSecurityPolicy {
    Write-LogWarn "Deshabilitando requisitos de complejidad y longitud de contraseñas locales (secedit)..."
    
    $CfgFile = "$env:TEMP\secpol.inf"
    secedit /export /cfg $CfgFile /Quiet | Out-Null
    
    # Leer el archivo respetando el encoding Unicode de Microsoft
    $Content = Get-Content $CfgFile -Encoding Unicode
    
    # Reemplazar la política sin importar espacios
    $Content = $Content -replace "(?i)^PasswordComplexity\s*=\s*1", "PasswordComplexity = 0"
    $Content = $Content -replace "(?i)^MinimumPasswordLength\s*=\s*\d+", "MinimumPasswordLength = 0"
    
    $Content | Set-Content $CfgFile -Encoding Unicode -Force
    
    # Re-importar y forzar
    secedit /configure /db $env:windir\security\local.sdb /cfg $CfgFile /areas SECURITYPOLICY /Quiet | Out-Null
    
    # Adicional para que no espere días en caducar contraseñas
    net accounts /maxpwage:unlimited /minpwlen:0 /minpwage:0 | Out-Null
    
    Write-LogSuccess "Restricciones de contraseña locales eliminadas."
}

# ==============================================================================
# 4. GESTIÓN DE USUARIOS 
# ==============================================================================

function Get-FtpUserVirtualDirectories ($Username) {
    # Eliminar espacios para evitar conflictos en PowerShell Path
    $Username = $Username.Trim()
    $VDirs = Get-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
    return $VDirs
}

function Create-FtpUser {
    param([string]$Username, [string]$Group, [string]$Password)

    # Validar Regex
    if ($Username -notmatch "^[a-z_][a-z0-9_-]{2,31}$") {
        Write-LogError "Nombre de usuario inválido. Use la convención clásica sin caracteres especiales raros."
    }

    # 1. Crear Usuario de Windows
    if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
        Write-LogWarn "El usuario local de Windows $Username ya existe. Configurando estructura FTP en IIS..."
    } else {
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $Username -Password $SecurePassword -Description "Automated FTP User" -AccountNeverExpires | Out-Null
        
        # Eliminarlo del grupo de usuarios estándar para evitar login interactivo RDP
        Remove-LocalGroupMember -Group "Users" -Member $Username -ErrorAction SilentlyContinue
        
        # Agregarlo a sus grupos de permisos FTP
        Add-LocalGroupMember -Group $Group -Member $Username
        Add-LocalGroupMember -Group "ftpusers" -Member $Username
        Write-LogSuccess "Usuario $Username creado y asignado a $Group y ftpusers."
    }

    # 2. Rutas Físicas. IIS exige que exista un LocalUser\$Username para aislarlo chroot.
    $UserRootDir = "$FtpRoot\LocalUser\$Username"
    if (-Not (Test-Path $UserRootDir)) {
        New-Item -Path $UserRootDir -ItemType Directory -Force | Out-Null
    }

    # ACL personal restrictiva (Chroot físico)
    $AclHome = Get-Acl $UserRootDir
    $AclHome.SetAccessRuleProtection($True, $False)
    $AclHome.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $AclHome.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Username, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $AclHome.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"))) # Requerido por IIS backend
    Set-Acl -Path $UserRootDir -AclObject $AclHome

    # 3. Mapear Carpetas Compartidas Virtualmente en IIS (La magia del "Bind Mount" de Windows)
    # Permite navegar a "/general" y "/reprobados" desde el chroot

    function Ensure-VirtualDirectory ($VirtualPath, $PhysicalPath) {
        $Name = $VirtualPath.Split('/')[-1]
        $AppPath = $VirtualPath.Substring(0, $VirtualPath.LastIndexOf('/'))
        
        $Exists = Get-WebVirtualDirectory -Site "AutomatedFTP" -Application $AppPath -Name $Name -ErrorAction SilentlyContinue
        if (-Not $Exists) {
            New-WebVirtualDirectory -Site "AutomatedFTP" -Name $Name -PhysicalPath $PhysicalPath -Application $AppPath -Force | Out-Null
            Write-LogInfo "Directorio Virtual IIS mapeado: $VirtualPath"
        }
    }

    Ensure-VirtualDirectory "/LocalUser/$username" $UserRootDir
    Ensure-VirtualDirectory "/LocalUser/$username/general" "$FtpRoot\general"
    Ensure-VirtualDirectory "/LocalUser/$username/$Group" "$FtpRoot\$Group"

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

    # Calcular grupo viejo
    $Principal = New-Object Security.Principal.NTAccount($Username)
    $OldGroups = (Get-LocalGroup | Where-Object { 
        ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty Name) -contains $Principal.Value 
    } | Select-Object -ExpandProperty Name)

    $OldGroup = ""
    if ($OldGroups -contains "reprobados") { $OldGroup = "reprobados" }
    elseif ($OldGroups -contains "recursadores") { $OldGroup = "recursadores" }

    if ($OldGroup -eq $NewGroup) {
        Write-LogSuccess "El usuario $Username ya se encuentra en el grupo $NewGroup. Nada qué hacer."
        return
    }

    Write-LogInfo "Iniciando migración de grupo para el usuario $Username ($OldGroup -> $NewGroup)..."

    # 1. Quitar del grupo Windows Viejo y poner en Nuevo
    if ($OldGroup) {
        Remove-LocalGroupMember -Group $OldGroup -Member $Username
    }
    Add-LocalGroupMember -Group $NewGroup -Member $Username
    
    # 2. Desvincular Directorio Virtual del Directorio Valido del Viejo Grupo en IIS
    $OldVDirPath = "/LocalUser/$Username/$OldGroup"
    if ($OldGroup -and (Get-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -Name $OldGroup -ErrorAction SilentlyContinue)) {
        Remove-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -Name $OldGroup -Force | Out-Null
        Write-LogInfo "Enlace virtual de IIS para $OldGroup eliminado de /LocalUser/$Username."
    }

    # 3. Vincular Nuevo Directorio Virtual en IIS
    if (-Not (Get-WebVirtualDirectory -Site "AutomatedFTP" -Application "/LocalUser/$Username" -Name $NewGroup -ErrorAction SilentlyContinue)) {
        New-WebVirtualDirectory -Site "AutomatedFTP" -Name $NewGroup -PhysicalPath "$FtpRoot\$NewGroup" -Application "/LocalUser/$Username" -Force | Out-Null
        Write-LogInfo "Enlace virtual nuevo mapeado: /LocalUser/$Username/$NewGroup apuntando a fisica de $NewGroup"
    }

    Write-LogSuccess "Migración completada exitosamente. $Username ahora pertenece exclusivamente a $NewGroup."
}

# ==============================================================================
# 5. MENÚ INTERACTIVO Y FLUJO NORMAL
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
                    # Ocultar contrasena al escribir
                    $sec = Read-Host "Contrasena" -AsSecureString
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
# 6. MANTENIMIENTO: PURGE, HELP, Y LIST
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

    # Localizar a todos los usuarios que pertenecen al grupo "ftpusers"
    if (Get-LocalGroup -Name "ftpusers" -ErrorAction SilentlyContinue) {
        $Members = Get-LocalGroupMember -Group "ftpusers" | Where-Object PrincipalSource -eq "Local"
        foreach ($Member in $Members) {
            $UserNameStr = ($Member.Name -split "\\")[1] # Remover nombre de dominio/máquina

            # Extraer su otro grupo principal
            $GrpList = (Get-LocalGroup | Where-Object { 
                ($_ | Get-LocalGroupMember -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -contains $Member.Name 
            } | Select-Object -ExpandProperty Name)

            $GrupoPrincipal = ""
            if ($GrpList -contains "reprobados") { $GrupoPrincipal = "reprobados" }
            elseif ($GrpList -contains "recursadores") { $GrupoPrincipal = "recursadores" }
            else { $GrupoPrincipal = "Generico" }

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

    Import-Module WebAdministration 

    # 1. Eliminar Sitio IIS 
    if (Test-Path "IIS:\Sites\AutomatedFTP") {
        Remove-WebSite -Name "AutomatedFTP" -Confirm:$false | Out-Null
        Write-LogInfo "Sitio FTP de IIS eliminado."
    }

    # 2. Eliminar Usuarios Locales 
    if (Get-LocalGroup -Name "ftpusers" -ErrorAction SilentlyContinue) {
        $Members = Get-LocalGroupMember -Group "ftpusers" | Where-Object PrincipalSource -eq "Local"
        foreach ($Member in $Members) {
            $UserNameStr = ($Member.Name -split "\\")[1]
            Remove-LocalUser -Name $UserNameStr -ErrorAction SilentlyContinue
            Write-LogInfo "Usuario Local de Windows [$UserNameStr] eliminado."
        }
    }

    # 3. Eliminar Grupos
    foreach ($G in @("ftpusers", "reprobados", "recursadores")) {
        if (Get-LocalGroup -Name $G -ErrorAction SilentlyContinue) {
            Remove-LocalGroup -Name $G -ErrorAction SilentlyContinue
        }
    }

    # 4. Eliminar Físicos
    if (Test-Path $FtpRoot) {
        Remove-Item -Path $FtpRoot -Recurse -Force -Confirm:$false
        Write-LogInfo "Directorios físicos eliminados."
    }

    # 5. Firewall Rules
    foreach ($RuleName in @("FTP-Server-Control", "FTP-Server-Secure", "FTP-Server-Passive")) {
        if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        }
    }

    Write-LogSuccess "Purgado exitoso. El servidor Windows ha regresado a la normalidad pre-script."
}

# ==============================================================================
# MAIN ENTRY POINT PARAMETRIZADO MANUAL
# ==============================================================================

# Parse args basic style since standard CmdletBinding disrupts seamless script dropping sometimes
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
        
        # Simple extraction
        $U = ""; $G = ""
        for ($i=1; $i -lt $args.Count; $i++) {
            if ($args[$i] -match "(?i)^-User$") { $U = $args[$i+1] }
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

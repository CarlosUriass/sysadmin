<#
.SYNOPSIS
Tarea 08 - Gobernanza, Cuotas y Control de Aplicaciones en Active Directory.
.DESCRIPTION
Orquestador que automatiza:
  1. Instalacion de roles (AD-DS, FSRM, GPMC)
  2. Estructura organizativa (OUs Cuates / NoCuates) desde CSV
  3. Logon Hours por grupo
  4. GPO de cierre forzado de sesion
  5. Cuotas FSRM (10 MB Cuates, 5 MB NoCuates)
  6. Apantallamiento de archivos (mp3, mp4, exe, msi)
  7. AppLocker (Notepad permitido Cuates, bloqueado por hash NoCuates)
#>

[CmdletBinding(DefaultParameterSetName = 'Full')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [Alias('i')]
    [switch]$Install,

    [Parameter(ParameterSetName = 'Setup')]
    [Alias('s')]
    [switch]$Setup,

    [Parameter(ParameterSetName = 'Quotas')]
    [Alias('q')]
    [switch]$Quotas,

    [Parameter(ParameterSetName = 'AppLock')]
    [Alias('a')]
    [switch]$AppLock,

    [Parameter(ParameterSetName = 'Status')]
    [switch]$Status,

    [Parameter(ParameterSetName = 'Help')]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==============================================================================
# LOGGING & UTILIDADES
# ==============================================================================
. "$PSScriptRoot\..\..\utils\logs\logger.ps1"

function Verificar-Administrador {
    & "$PSScriptRoot\..\..\utils\ps1\permissions.ps1" -CheckAdmin
    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Ejecutar como administrador."
    }
}

# ==============================================================================
# CONSTANTES
# ==============================================================================
$CSV_PATH    = "$PSScriptRoot\users.csv"
$SHARE_ROOT  = "C:\Shares\Users"
$OU_CUATES   = "Cuates"
$OU_NOCUATES = "NoCuates"
$GPO_NAME    = "Forzar Cierre Sesion"
$FG_NAME     = "Archivos Bloqueados"

function Obtener-DominioBase {
    $dom = (Get-ADDomain).DistinguishedName
    return $dom
}

# ==============================================================================
# 1. INSTALACION DE ROLES
# ==============================================================================
function Instalar-Roles {
    Write-LogInfo "=== instalacion de roles ==="

    $roles = @('AD-Domain-Services', 'FS-Resource-Manager', 'GPMC')
    foreach ($r in $roles) {
        Write-LogInfo "verificando rol: $r"
        & "$PSScriptRoot\..\..\utils\ps1\install_feature.ps1" -FeatureName $r -IncludeAllSubFeature
    }

    # Asegurar servicio FSRM activo
    $svc = Get-Service -Name 'srmsvc' -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -ne 'Automatic') { Set-Service -Name 'srmsvc' -StartupType Automatic }
        if ($svc.Status -ne 'Running')      { Start-Service -Name 'srmsvc' }
        Write-LogSuccess "servicio FSRM activo"
    }

    Write-LogSuccess "roles instalados"
}

# ==============================================================================
# 1b. PROMOCION DE DOMINIO (si aun no es DC)
# ==============================================================================
function Promover-Dominio {
    Write-LogInfo "=== verificando promocion de dominio ==="

    # Verificar si ya es un Domain Controller
    $adws = Get-Service -Name 'ADWS' -ErrorAction SilentlyContinue
    if ($adws -and $adws.Status -eq 'Running') {
        try {
            $null = Get-ADDomain -ErrorAction Stop
            Write-LogInfo "servidor ya es Domain Controller"
            return
        } catch { }
    }

    Write-LogWarn "el servidor NO esta promovido como Domain Controller"

    # Solicitar datos del dominio
    $domName = Read-Host "nombre del dominio a crear (ej. laboratorio.local)"
    if ([string]::IsNullOrWhiteSpace($domName)) {
        Write-LogError "nombre de dominio vacio"
    }

    $netbios = ($domName.Split('.')[0]).ToUpper()
    Write-LogInfo "NetBIOS name: $netbios"

    # Solicitar password de DSRM
    $dsrmPass = Read-Host "password de DSRM (Directory Services Restore Mode)" -AsSecureString

    Write-LogInfo "promoviendo servidor a Domain Controller para $domName ..."

    Import-Module ADDSDeployment -ErrorAction Stop

    Install-ADDSForest `
        -DomainName $domName `
        -DomainNetbiosName $netbios `
        -SafeModeAdministratorPassword $dsrmPass `
        -InstallDns:$true `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -NoRebootOnCompletion:$false `
        -Force:$true

    # Si llega aqui sin reiniciar (poco probable), avisar
    Write-LogWarn "el servidor debe reiniciarse para completar la promocion"
    Write-LogWarn "despues del reinicio, ejecute este script nuevamente con: .\governance.ps1 -s"
    exit 0
}

# ==============================================================================
# 2. ESTRUCTURA ORGANIZATIVA (OUs + Usuarios desde CSV)
# ==============================================================================
function Crear-EstructuraOU {
    Write-LogInfo "=== estructura organizativa ==="

    $baseDN = Obtener-DominioBase

    # --- Crear OUs ---
    foreach ($ou in @($OU_CUATES, $OU_NOCUATES)) {
        $ouDN = "OU=$ou,$baseDN"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $ou -Path $baseDN -ProtectedFromAccidentalDeletion $false
            Write-LogSuccess "OU creada: $ou"
        } else {
            Write-LogInfo "OU ya existe: $ou"
        }
    }

    # --- Crear grupos de seguridad ---
    foreach ($grp in @("Grupo$OU_CUATES", "Grupo$OU_NOCUATES")) {
        $ouName = $grp -replace '^Grupo', ''
        $ouDN   = "OU=$ouName,$baseDN"
        if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security -Path $ouDN
            Write-LogSuccess "grupo creado: $grp"
        } else {
            Write-LogInfo "grupo ya existe: $grp"
        }
    }

    # --- Importar usuarios desde CSV ---
    if (-not (Test-Path $CSV_PATH)) {
        Write-LogError "CSV no encontrado: $CSV_PATH"
    }

    $usuarios = Import-Csv -Path $CSV_PATH
    Write-LogInfo "importando $($usuarios.Count) usuarios desde CSV"

    foreach ($u in $usuarios) {
        $ouTarget = if ($u.Departamento -eq 'Cuates') { $OU_CUATES } else { $OU_NOCUATES }
        $ouDN     = "OU=$ouTarget,$baseDN"
        $grpName  = "Grupo$ouTarget"
        $sam      = $u.Usuario
        $upn      = "$sam@$((Get-ADDomain).DNSRoot)"

        if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
            $secPwd = ConvertTo-SecureString $u.Password -AsPlainText -Force
            New-ADUser -Name "$($u.Nombre) $($u.Apellido)" `
                       -GivenName $u.Nombre `
                       -Surname $u.Apellido `
                       -SamAccountName $sam `
                       -UserPrincipalName $upn `
                       -Path $ouDN `
                       -AccountPassword $secPwd `
                       -Enabled $true `
                       -PasswordNeverExpires $true `
                       -ChangePasswordAtLogon $false `
                       -Department $u.Departamento
            Write-LogSuccess "usuario creado: $sam -> OU=$ouTarget"
        } else {
            Write-LogInfo "usuario ya existe: $sam"
        }

        # Agregar al grupo correspondiente
        try {
            Add-ADGroupMember -Identity $grpName -Members $sam -ErrorAction SilentlyContinue
        } catch { }
    }

    Write-LogSuccess "estructura organizativa completa"
}

# ==============================================================================
# 3. LOGON HOURS
# ==============================================================================
function Configurar-LogonHours {
    Write-LogInfo "=== logon hours ==="

    <#
    Logon Hours usa un byte array de 21 bytes (168 bits = 7 dias x 24 horas).
    Cada bit = 1 hora. Bit en 1 = permitido, 0 = denegado.
    Orden: Domingo(0-23), Lunes(0-23), ..., Sabado(0-23)
    Cada dia = 3 bytes (24 bits). Byte 0 = horas 0-7, Byte 1 = horas 8-15, Byte 2 = horas 16-23.
    Bits dentro de cada byte van de LSB (hora menor) a MSB (hora mayor).
    #>

    function New-LogonHoursArray {
        param(
            [int]$StartHour,
            [int]$EndHour   # exclusivo; si End < Start se interpreta como cruce de medianoche
        )

        [byte[]]$hours = New-Object byte[] 21

        for ($day = 0; $day -lt 7; $day++) {
            for ($hour = 0; $hour -lt 24; $hour++) {
                $allowed = $false
                if ($StartHour -le $EndHour) {
                    # rango normal (ej. 8-15)
                    if ($hour -ge $StartHour -and $hour -lt $EndHour) { $allowed = $true }
                } else {
                    # cruce de medianoche (ej. 15-02 => 15-24 y 0-02)
                    if ($hour -ge $StartHour -or $hour -lt $EndHour) { $allowed = $true }
                }

                if ($allowed) {
                    $bitIndex  = ($day * 24) + $hour
                    $byteIndex = [math]::Floor($bitIndex / 8)
                    $bitOffset = $bitIndex % 8
                    $hours[$byteIndex] = $hours[$byteIndex] -bor (1 -shl $bitOffset)
                }
            }
        }
        return $hours
    }

    # Cuates: 8:00 AM - 3:00 PM (08-15)
    $hoursCuates = New-LogonHoursArray -StartHour 8 -EndHour 15
    # NoCuates: 3:00 PM - 2:00 AM (15-02, cruce de medianoche)
    $hoursNoCuates = New-LogonHoursArray -StartHour 15 -EndHour 2

    $baseDN = Obtener-DominioBase

    # Aplicar a usuarios de cada OU
    $cuatesUsers = Get-ADUser -SearchBase "OU=$OU_CUATES,$baseDN" -Filter * -ErrorAction SilentlyContinue
    foreach ($u in $cuatesUsers) {
        Set-ADUser -Identity $u -Clear logonhours
        Set-ADUser -Identity $u -Replace @{ logonhours = [byte[]]$hoursCuates }
        Write-LogInfo "logon hours cuates aplicado: $($u.SamAccountName) (08:00-15:00)"
    }

    $noCuatesUsers = Get-ADUser -SearchBase "OU=$OU_NOCUATES,$baseDN" -Filter * -ErrorAction SilentlyContinue
    foreach ($u in $noCuatesUsers) {
        Set-ADUser -Identity $u -Clear logonhours
        Set-ADUser -Identity $u -Replace @{ logonhours = [byte[]]$hoursNoCuates }
        Write-LogInfo "logon hours no-cuates aplicado: $($u.SamAccountName) (15:00-02:00)"
    }

    Write-LogSuccess "logon hours configurado"
}

# ==============================================================================
# 4. GPO — CIERRE FORZADO DE SESION
# ==============================================================================
function Configurar-GPOCierreSesion {
    Write-LogInfo "=== GPO cierre forzado de sesion ==="

    $baseDN  = Obtener-DominioBase
    $dnsRoot = (Get-ADDomain).DNSRoot

    # Crear GPO si no existe
    $gpo = Get-GPO -Name $GPO_NAME -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $GPO_NAME -Comment "Forzar cierre de sesion al expirar logon hours"
        Write-LogSuccess "GPO creada: $GPO_NAME"
    } else {
        Write-LogInfo "GPO ya existe: $GPO_NAME"
    }

    # Configurar la clave de registro para forzar logoff
    # Ruta: Computer Configuration > Policies > Windows Settings > Security Settings >
    #        Local Policies > Security Options > "Network security: Force logoff when logon hours expire"
    Set-GPRegistryValue -Name $GPO_NAME `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -ValueName "ForceLogoffWhenHourExpire" `
        -Type DWord `
        -Value 1

    Write-LogInfo "clave ForceLogoffWhenHourExpire = 1 configurada"

    # Vincular GPO al dominio
    try {
        New-GPLink -Name $GPO_NAME -Target $baseDN -LinkEnabled Yes -ErrorAction Stop
        Write-LogSuccess "GPO vinculada al dominio"
    } catch {
        Write-LogInfo "GPO ya vinculada (o error de vinculacion: $($_.Exception.Message))"
    }

    # Forzar actualizacion de politicas
    Write-LogInfo "forzando gpupdate..."
    gpupdate /force | Out-Null

    Write-LogSuccess "GPO de cierre forzado configurada"
}

# ==============================================================================
# 5. FSRM — CUOTAS DE ALMACENAMIENTO
# ==============================================================================
function Configurar-Cuotas {
    Write-LogInfo "=== cuotas FSRM ==="

    # Crear carpeta raiz de shares
    if (-not (Test-Path $SHARE_ROOT)) {
        New-Item -ItemType Directory -Path $SHARE_ROOT -Force | Out-Null
        Write-LogSuccess "carpeta raiz creada: $SHARE_ROOT"
    }

    # Compartir la carpeta raiz
    $shareName = "Users"
    $existing  = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-SmbShare -Name $shareName -Path $SHARE_ROOT -FullAccess "Everyone" | Out-Null
        Write-LogSuccess "share creado: \\${env:COMPUTERNAME}\${shareName}"
    } else {
        Write-LogInfo "share ya existe: $shareName"
    }

    $baseDN   = Obtener-DominioBase
    $usuarios = Import-Csv -Path $CSV_PATH

    foreach ($u in $usuarios) {
        $sam       = $u.Usuario
        $userPath  = Join-Path $SHARE_ROOT $sam
        $quotaSize = if ($u.Departamento -eq 'Cuates') { 10MB } else { 5MB }
        $quotaLabel = if ($u.Departamento -eq 'Cuates') { "10 MB" } else { "5 MB" }

        # Crear carpeta personal
        if (-not (Test-Path $userPath)) {
            New-Item -ItemType Directory -Path $userPath -Force | Out-Null
        }

        # Asignar permisos NTFS al usuario
        $acl = Get-Acl $userPath
        $dnsRoot = (Get-ADDomain).DNSRoot
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$dnsRoot\$sam", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $userPath -AclObject $acl

        # Crear cuota FSRM
        $existingQuota = Get-FsrmQuota -Path $userPath -ErrorAction SilentlyContinue
        if (-not $existingQuota) {
            New-FsrmQuota -Path $userPath -Size $quotaSize -Description "Cuota ${quotaLabel} para ${sam}"
            Write-LogSuccess "cuota ${quotaLabel} aplicada: ${sam}"
        } else {
            # Actualizar si el tamano cambio
            if ($existingQuota.Size -ne $quotaSize) {
                Set-FsrmQuota -Path $userPath -Size $quotaSize
                Write-LogInfo "cuota actualizada a ${quotaLabel}: ${sam}"
            } else {
                Write-LogInfo "cuota ya configurada: ${sam} (${quotaLabel})"
            }
        }
    }

    Write-LogSuccess "cuotas FSRM configuradas"
}

# ==============================================================================
# 6. FSRM — APANTALLAMIENTO DE ARCHIVOS (FILE SCREENING)
# ==============================================================================
function Configurar-FileScreening {
    Write-LogInfo "=== apantallamiento de archivos ==="

    # Crear grupo de archivos bloqueados
    $fg = Get-FsrmFileGroup -Name $FG_NAME -ErrorAction SilentlyContinue
    if (-not $fg) {
        New-FsrmFileGroup -Name $FG_NAME -IncludePattern @("*.mp3", "*.mp4", "*.exe", "*.msi")
        Write-LogSuccess "grupo de archivos creado: $FG_NAME"
    } else {
        # Actualizar patrones si es necesario
        Set-FsrmFileGroup -Name $FG_NAME -IncludePattern @("*.mp3", "*.mp4", "*.exe", "*.msi")
        Write-LogInfo "grupo de archivos ya existe: $FG_NAME"
    }

    # Aplicar file screen activo a cada carpeta de usuario
    $usuarios = Import-Csv -Path $CSV_PATH
    foreach ($u in $usuarios) {
        $userPath = Join-Path $SHARE_ROOT $u.Usuario

        if (Test-Path $userPath) {
            $existingScreen = Get-FsrmFileScreen -Path $userPath -ErrorAction SilentlyContinue
            if (-not $existingScreen) {
                New-FsrmFileScreen -Path $userPath -Active -IncludeGroup @($FG_NAME) `
                    -Description "Bloqueo de archivos multimedia y ejecutables"
                Write-LogSuccess "file screen activo aplicado: $($u.Usuario)"
            } else {
                Write-LogInfo "file screen ya existe: $($u.Usuario)"
            }
        }
    }

    Write-LogSuccess "apantallamiento de archivos configurado"
}

# ==============================================================================
# 7. APPLOCKER
# ==============================================================================
function Configurar-AppLocker {
    Write-LogInfo "=== AppLocker ==="

    # Asegurar servicio AppIDSvc activo
    $svc = Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -ne 'Automatic') {
            Set-Service -Name 'AppIDSvc' -StartupType Automatic
        }
        if ($svc.Status -ne 'Running') {
            Start-Service -Name 'AppIDSvc'
        }
        Write-LogSuccess "servicio AppIDSvc activo"
    } else {
        Write-LogWarn "servicio AppIDSvc no encontrado"
    }

    $dnsRoot     = (Get-ADDomain).DNSRoot
    $grpCuates   = "Grupo$OU_CUATES"
    $grpNoCuates = "Grupo$OU_NOCUATES"
    $notepadPath = "$env:SystemRoot\System32\notepad.exe"

    # Obtener informacion de hash de notepad.exe
    Write-LogInfo "obteniendo hash de $notepadPath ..."
    $fileInfo = Get-AppLockerFileInformation -Path $notepadPath -ErrorAction Stop

    # -----------------------------------------------
    # Construir politica XML de AppLocker
    # -----------------------------------------------
    # Necesitamos:
    #  - Reglas default de ejecutable (para que el sistema funcione)
    #  - Allow notepad para GrupoCuates
    #  - Deny notepad por hash para GrupoNoCuates

    $hashValue = $fileInfo.Hash.HashDataString
    $hashType  = $fileInfo.Hash.HashType
    $fileLen   = (Get-Item $notepadPath).Length
    $fileName  = [System.IO.Path]::GetFileName($notepadPath)

    # Obtener SIDs de los grupos de AD
    $sidCuates   = (Get-ADGroup $grpCuates).SID.Value
    $sidNoCuates = (Get-ADGroup $grpNoCuates).SID.Value

    $policyXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- Regla default: Permitir todo para Administradores -->
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="Permitir todo para Administradores"
                  Description="Regla default"
                  UserOrGroupSid="S-1-5-32-544"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

    <!-- Regla default: Permitir archivos de Program Files para todos -->
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51"
                  Name="Permitir Program Files"
                  Description="Regla default"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <!-- Regla default: Permitir archivos de Windows para todos -->
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="Permitir Windows"
                  Description="Regla default"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <!-- ALLOW: Notepad para GrupoCuates -->
    <FileHashRule Id="b5a0e3f2-1c4d-4e5f-8a6b-7c8d9e0f1a2b"
                  Name="Permitir Notepad para Cuates"
                  Description="El grupo Cuates puede usar Bloc de Notas"
                  UserOrGroupSid="$sidCuates"
                  Action="Allow">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="$hashType" Data="$hashValue"
                    SourceFileName="$fileName" SourceFileLength="$fileLen" />
        </FileHashCondition>
      </Conditions>
    </FileHashRule>

    <!-- DENY: Notepad por hash para GrupoNoCuates -->
    <FileHashRule Id="c6b1f4a3-2d5e-4f6a-9b7c-8d9e0f1a2b3c"
                  Name="Bloquear Notepad para NoCuates"
                  Description="El grupo NoCuates tiene bloqueado el Bloc de Notas por hash"
                  UserOrGroupSid="$sidNoCuates"
                  Action="Deny">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="$hashType" Data="$hashValue"
                    SourceFileName="$fileName" SourceFileLength="$fileLen" />
        </FileHashCondition>
      </Conditions>
    </FileHashRule>

  </RuleCollection>
</AppLockerPolicy>
"@

    # Aplicar politica
    $tempXml = "$env:TEMP\applocker_policy.xml"
    Set-Content -Path $tempXml -Value $policyXml -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy $tempXml -Merge
    Remove-Item $tempXml -ErrorAction SilentlyContinue

    Write-LogSuccess "politica AppLocker aplicada"
    Write-LogInfo "  - Notepad PERMITIDO para $grpCuates"
    Write-LogInfo "  - Notepad BLOQUEADO (hash) para $grpNoCuates"

    # Forzar gpupdate
    gpupdate /force | Out-Null
    Write-LogSuccess "AppLocker configurado"
}

# ==============================================================================
# 8. CHECKLIST DIAGNOSTICA
# ==============================================================================
function Mostrar-Estado {
    Write-Host ""
    Write-Host "--- checklist diagnostica ---" -ForegroundColor White

    function Test-Check {
        param([string]$Name, [bool]$Eval)
        if ($Eval) { Write-Host "  $($Name): ok" -ForegroundColor Green }
        else       { Write-Host "  $($Name): fail" -ForegroundColor Red }
    }

    $baseDN = Obtener-DominioBase

    # OUs
    $ouCOk = [bool](Get-ADOrganizationalUnit -Filter "Name -eq '$OU_CUATES'" -ErrorAction SilentlyContinue)
    $ouNOk = [bool](Get-ADOrganizationalUnit -Filter "Name -eq '$OU_NOCUATES'" -ErrorAction SilentlyContinue)
    Test-Check "OU Cuates" $ouCOk
    Test-Check "OU NoCuates" $ouNOk

    # Grupos
    $grpCOk = [bool](Get-ADGroup -Filter "Name -eq 'Grupo$OU_CUATES'" -ErrorAction SilentlyContinue)
    $grpNOk = [bool](Get-ADGroup -Filter "Name -eq 'Grupo$OU_NOCUATES'" -ErrorAction SilentlyContinue)
    Test-Check "Grupo Cuates" $grpCOk
    Test-Check "Grupo NoCuates" $grpNOk

    # Usuarios
    $totalCuates = 0; $totalNoCuates = 0
    try { $totalCuates   = @(Get-ADUser -SearchBase "OU=$OU_CUATES,$baseDN" -Filter * -ErrorAction Stop).Count } catch { }
    try { $totalNoCuates = @(Get-ADUser -SearchBase "OU=$OU_NOCUATES,$baseDN" -Filter * -ErrorAction Stop).Count } catch { }
    Test-Check "usuarios en Cuates ($totalCuates)" ($totalCuates -gt 0)
    Test-Check "usuarios en NoCuates ($totalNoCuates)" ($totalNoCuates -gt 0)

    # GPO
    $gpoOk = [bool](Get-GPO -Name $GPO_NAME -ErrorAction SilentlyContinue)
    Test-Check "GPO '$GPO_NAME'" $gpoOk

    # FSRM
    $fsrmSvc = Get-Service -Name 'srmsvc' -ErrorAction SilentlyContinue
    Test-Check "servicio FSRM" ($fsrmSvc -and $fsrmSvc.Status -eq 'Running')

    $quotas = @(Get-FsrmQuota -ErrorAction SilentlyContinue)
    Test-Check "cuotas FSRM ($($quotas.Count))" ($quotas.Count -gt 0)

    $screens = @(Get-FsrmFileScreen -ErrorAction SilentlyContinue)
    Test-Check "file screens ($($screens.Count))" ($screens.Count -gt 0)

    # AppLocker
    $appIdSvc = Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue
    Test-Check "servicio AppIDSvc" ($appIdSvc -and $appIdSvc.Status -eq 'Running')

    # Share
    $shareOk = [bool](Get-SmbShare -Name 'Users' -ErrorAction SilentlyContinue)
    Test-Check "share \\$env:COMPUTERNAME\Users" $shareOk

    Write-Host ""
}

# ==============================================================================
# AYUDA
# ==============================================================================
function Mostrar-Ayuda {
    Write-Host "uso: .\governance.ps1 [opcion]"
    Write-Host "  -i  instalar roles      -s  setup (OUs, usuarios, logon hours, GPO)"
    Write-Host "  -q  cuotas + screening   -a  AppLocker"
    Write-Host "  -Status  checklist       -h  ayuda"
    Write-Host "  sin opciones = flujo completo"
}

# ==============================================================================
# MAIN
# ==============================================================================
Write-Host "=== Tarea 08: Gobernanza, Cuotas y Control de Aplicaciones ===" -ForegroundColor White

if ($Help)   { Mostrar-Ayuda; exit 0 }
if ($Status) { Mostrar-Estado; exit 0 }

Verificar-Administrador

if ($Install) {
    Instalar-Roles
    Promover-Dominio
}
elseif ($Setup) {
    Promover-Dominio
    Crear-EstructuraOU
    Configurar-LogonHours
    Configurar-GPOCierreSesion
}
elseif ($Quotas) {
    Configurar-Cuotas
    Configurar-FileScreening
}
elseif ($AppLock) {
    Configurar-AppLocker
}
else {
    # Flujo completo
    Instalar-Roles
    Promover-Dominio
    Crear-EstructuraOU
    Configurar-LogonHours
    Configurar-GPOCierreSesion
    Configurar-Cuotas
    Configurar-FileScreening
    Configurar-AppLocker
    Mostrar-Estado
}

Write-LogSuccess "proceso completado"

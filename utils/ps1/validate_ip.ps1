[cmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [Alias("i")]
    [string]$IP,

    [switch]$Help
)

if ($Help) {
    Write-Host "Uso: .\validate_ip.ps1 -IP <direccion>"
    exit 0
}

if ($IP -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
    exit 1
}

foreach ($o in $Matches[1..4]) {
    if ([int]$o -gt 255) {
        exit 1
    }
}

exit 0

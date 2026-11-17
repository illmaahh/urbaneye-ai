$ErrorActionPreference = 'Stop'
$env:HOST = '127.0.0.1'
$env:PORT = '8000'
$env:COOKIE_SECURE = '0'
$env:URBANEYE_DATA_DIR = Join-Path $PSScriptRoot '.urbaneye-data'

$envFile = Join-Path $PSScriptRoot '.env'
if (-not (Test-Path -LiteralPath $envFile)) {
    $randomBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($randomBytes)
    $invite = [Convert]::ToBase64String($randomBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    Set-Content -LiteralPath $envFile -Value "URBANEYE_ADMIN_INVITE=$invite" -Encoding ascii
    Write-Host "One-time setup: use this administrator invite when creating your account: $invite" -ForegroundColor Yellow
}
$adminLine = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^URBANEYE_ADMIN_INVITE=' } | Select-Object -First 1
if ($adminLine) { $env:URBANEYE_ADMIN_INVITE = $adminLine.Substring('URBANEYE_ADMIN_INVITE='.Length) }

Write-Host 'Starting UrbanEye AI with shared server-side accounts and reports.' -ForegroundColor Cyan
python (Join-Path $PSScriptRoot 'server.py')

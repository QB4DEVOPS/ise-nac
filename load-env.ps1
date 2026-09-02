# Load ISE_HOST, ISE_USERNAME, ISE_PASSWORD from .env into this PowerShell window.
# From the repo folder, paste:
#   . .\load-env.ps1

$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path -LiteralPath $envFile)) {
    Write-Host "Missing .env"
    Write-Host "Copy .env.example to .env, put the lab password in, save."
    Write-Host "copy .env.example .env"
    Write-Host "notepad .env"
    return
}

Get-Content -LiteralPath $envFile | ForEach-Object {
    $line = $_
    if ($null -eq $line) { return }
    $line = $line.Trim().TrimStart([char]0xFEFF)
    if ($line -eq "" -or $line.StartsWith("#")) { return }
    $eq = $line.IndexOf("=")
    if ($eq -lt 1) { return }
    $name = $line.Substring(0, $eq).Trim()
    $value = $line.Substring($eq + 1).Trim()
    if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    Set-Item -Path "Env:$name" -Value $value
}

if ($env:ISE_HOST) {
    $env:TF_VAR_ise_host = $env:ISE_HOST
}
if ($env:ISE_USERNAME) {
    $env:TF_VAR_ise_username = $env:ISE_USERNAME
}
if ($env:NAD_TACACS_SECRET) {
    $env:TF_VAR_nad_tacacs_secret = $env:NAD_TACACS_SECRET
}
if ($env:NAD_RADIUS_SECRET) {
    $env:TF_VAR_nad_radius_secret = $env:NAD_RADIUS_SECRET
}
if ($env:USER_PASSWORD_DEFAULT) {
    $env:TF_VAR_user_password = $env:USER_PASSWORD_DEFAULT
}
if ($env:USER_ENABLE_PASSWORD_DEFAULT) {
    $env:TF_VAR_user_enable_password = $env:USER_ENABLE_PASSWORD_DEFAULT
}

Write-Host "Loaded .env. PAN host: $($env:ISE_HOST)"
if (-not $env:NAD_TACACS_SECRET -or -not $env:NAD_RADIUS_SECRET) {
    Write-Host "NAD_TACACS_SECRET and NAD_RADIUS_SECRET are both required for a normal apply (default 15000 NADs)."
    if (-not $env:NAD_TACACS_SECRET) {
        Write-Host "NAD_TACACS_SECRET is empty. Set it in .env."
    }
    if (-not $env:NAD_RADIUS_SECRET) {
        Write-Host "NAD_RADIUS_SECRET is empty. NAD protocol is RADIUS (802.1X/MAB). Set it in .env."
    }
    Write-Host "Policy-only (no switches): `$env:TF_VAR_nad_count = `"0`""
}
if (-not $env:USER_PASSWORD_DEFAULT) {
    Write-Host "USER_PASSWORD_DEFAULT is required for a normal apply (default 8 lab Internal Users)."
    Write-Host "USER_PASSWORD_DEFAULT is empty. Set it in .env."
    Write-Host "Skip Internal User rows: `$env:TF_VAR_user_count = `"0`""
}
Write-Host "Next: terraform init   then   terraform plan   then   terraform apply"

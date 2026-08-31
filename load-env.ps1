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

Write-Host "Loaded .env. PAN host: $($env:ISE_HOST)"
Write-Host "Next: terraform init   then   terraform plan   then   terraform apply"

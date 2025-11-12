$ShareFolder = "$env:USERPROFILE\Desktop\shares"
$BinaryName = "tservice.exe"

Write-Host "Building service..." -ForegroundColor Green
cargo build --release

$SourcePath = ".\target\release\$BinaryName"
$DestPath = "$ShareFolder\$BinaryName"

if (-not (Test-Path $SourcePath)) {
    Write-Host "Error: Binary not found at $SourcePath" -ForegroundColor Red
    exit 1
}

# Create share folder if not exists
if (-not (Test-Path $ShareFolder)) {
    New-Item -ItemType Directory -Path $ShareFolder | Out-Null
}

Write-Host "Copying binary to share folder..." -ForegroundColor Green
Copy-Item $SourcePath $DestPath -Force

Write-Host "Done! Binary copied to: $DestPath" -ForegroundColor Cyan

$ServiceName = "TedrUserService"
$ServiceDisplayName = "Tedr User Mode Service"
$ServiceDescription = "User-mode service for Tedr minifilter communication"
$ShareFolder = "$env:USERPROFILE\Desktop\shares"
$BinaryName = "tservice.exe"
$InstallPath = "C:\Services\Tedr"
$ExePath = "$InstallPath\$BinaryName"

# Create install directory
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

# Check if service exists
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($service) {
    Write-Host "Service exists. Reloading with new binary..." -ForegroundColor Yellow
    
    # Stop service
    if ($service.Status -eq 'Running') {
        Write-Host "Stopping service..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 3
    }
    
    # Copy new binary
    Write-Host "Copying new binary..." -ForegroundColor Green
    Copy-Item "$ShareFolder\$BinaryName" $ExePath -Force
    
    # Start service
    Write-Host "Starting service..." -ForegroundColor Green
    Start-Service -Name $ServiceName
    
} else {
    Write-Host "Service not found. Installing..." -ForegroundColor Green
    
    # Copy binary
    Copy-Item "$ShareFolder\$BinaryName" $ExePath -Force
    
    # Create service
    sc.exe create $ServiceName binPath= "$ExePath" DisplayName= "$ServiceDisplayName" start= auto
    sc.exe description $ServiceName "$ServiceDescription"
    
    # Start service
    Write-Host "Starting service..." -ForegroundColor Green
    sc.exe start $ServiceName
}

# Show status
Write-Host "`nUser Service Status:" -ForegroundColor Cyan
sc.exe query $ServiceName

Write-Host "`nKernel Driver Status:" -ForegroundColor Cyan
sc.exe query tedr

Write-Host "`nLog location: c:\logs\tservice.log" -ForegroundColor Cyan
Write-Host "`nNote: Make sure kernel driver is loaded first!" -ForegroundColor Yellow

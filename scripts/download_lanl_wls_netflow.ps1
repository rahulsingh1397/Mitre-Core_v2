#!/usr/bin/env powershell
<#
.SYNOPSIS
    Download LANL 2017 Unified Host and Network Dataset (WLS + Netflow)

.DESCRIPTION
    Downloads Windows Logging Service and Netflow files from LANL CSR
    to separate HostEvents and Netflow folders.

.USAGE
    .\download_lanl_wls_netflow.ps1 -Days 1-90
    .\download_lanl_wls_netflow.ps1 -Days 1-10 -SkipNetflow
    .\download_lanl_wls_netflow.ps1 -Resume
#>

[CmdletBinding()]
param(
    [string]$Days = "1-90",
    [switch]$SkipNetflow,
    [switch]$SkipWLS,
    [switch]$Resume,
    [int]$MaxRetries = 3,
    [int]$TimeoutSeconds = 300
)

$baseUrl = "https://csr.lanl.gov/data-fence/1773708832/t6n0YSZ8oj3sryq_pv65F-YWxaA=unified-host-network-dataset-2017"
$datasetRoot = Get-ChildItem -Path "E:\Private\MITRE-CORE 2\MITRE-CORE_V2\datasets" -Filter "LANL*" | Select-Object -First 1 -ExpandProperty FullName
$hostEventsDir = Join-Path $datasetRoot "HostEvents"
$netflowDir = Join-Path $datasetRoot "Netflow"

# Parse day range
$dayRange = $Days -split "-"
$startDay = [int]$dayRange[0]
$endDay = [int]$dayRange[1]

Write-Host "LANL Dataset Downloader" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host "HostEvents folder: $hostEventsDir"
Write-Host "Netflow folder: $netflowDir"
Write-Host "Day range: $startDay to $endDay"
Write-Host ""

# Ensure directories exist
New-Item -ItemType Directory -Path $hostEventsDir -Force | Out-Null
New-Item -ItemType Directory -Path $netflowDir -Force | Out-Null

# Track statistics
$stats = @{
    TotalFiles = 0
    Downloaded = 0
    Failed = 0
    Skipped = 0
    TotalBytes = 0
}

function Start-LANLDownload {
    param(
        [string]$Url,
        [string]$OutPath,
        [string]$Description
    )

    $fileName = Split-Path $OutPath -Leaf
    $stats.TotalFiles++

    # Check if file already exists and is valid
    if (Test-Path $OutPath) {
        $existingSize = (Get-Item $OutPath).Length

        if ($existingSize -gt 10000) {
            Write-Host "  [SKIP] $fileName already exists ($([math]::Round($existingSize/1MB, 1)) MB)" -ForegroundColor Gray
            $stats.Skipped++
            return $true
        } elseif ($Resume -and $existingSize -gt 100) {
            Write-Host "  [RESUME] $fileName ($([math]::Round($existingSize/1KB, 1)) KB)" -ForegroundColor Yellow
        } else {
            # File exists but is too small, delete it
            Remove-Item $OutPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "  [DOWNLOAD] $Description..." -ForegroundColor Blue -NoNewline

    $retryCount = 0
    $success = $false

    while ($retryCount -lt $MaxRetries -and -not $success) {
        try {
            $webHeaders = @{
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                "Referer" = "https://csr.lanl.gov/data/unified-host-network-dataset-2017/"
            }

            $irmParams = @{
                Uri = $Url
                OutFile = $OutPath
                Headers = $webHeaders
                TimeoutSec = $TimeoutSeconds
                ErrorAction = "Stop"
            }

            if ($Resume -and (Test-Path $OutPath)) {
                $existingSize = (Get-Item $OutPath).Length
                $irmParams['Resume'] = $true
            }

            Invoke-WebRequest @irmParams

            # Verify download
            if (Test-Path $OutPath) {
                $fileSize = (Get-Item $OutPath).Length
                if ($fileSize -gt 1000) {
                    $stats.Downloaded++
                    $stats.TotalBytes += $fileSize
                    Write-Host " OK ($([math]::Round($fileSize/1MB, 1)) MB)" -ForegroundColor Green
                    $success = $true
                } else {
                    Write-Host " FAIL (file too small: $fileSize bytes)" -ForegroundColor Red
                    Remove-Item $OutPath -Force -ErrorAction SilentlyContinue
                    $retryCount++
                    Start-Sleep -Seconds 2
                }
            } else {
                Write-Host " FAIL (file not created)" -ForegroundColor Red
                $retryCount++
                Start-Sleep -Seconds 2
            }
        }
        catch {
            Write-Host " ERROR: $($_.Exception.Message)" -ForegroundColor Red
            $retryCount++
            Start-Sleep -Seconds 2
        }
    }

    if (-not $success) {
        $stats.Failed++
        Write-Host "  [FAILED] $fileName after $MaxRetries attempts" -ForegroundColor Red
    }

    return $success
}

Write-Host ""
Write-Host "NOTE: The LANL server requires browser authentication." -ForegroundColor Yellow
Write-Host "If you see 401 errors, please download manually from:" -ForegroundColor Yellow
Write-Host "  https://csr.lanl.gov/data/unified-host-network-dataset-2017/" -ForegroundColor Cyan
Write-Host ""
Write-Host "Save files to:"
Write-Host "  WLS files -> $hostEventsDir"
Write-Host "  Netflow files -> $netflowDir"
Write-Host ""

# Calculate total files
$totalWLS = if ($SkipWLS) { 0 } else { $endDay - $startDay + 1 }
$totalNetflow = if ($SkipNetflow) { 0 } else { $endDay - $startDay + 1 }

Write-Host "Total files to download: $($totalWLS + $totalNetflow)" -ForegroundColor Cyan
Write-Host ""

# Download WLS files
if (-not $SkipWLS) {
    Write-Host "Downloading Windows Logging Service (WLS) files..." -ForegroundColor Cyan
    Write-Host "---------------------------------------------------" -ForegroundColor Cyan

    for ($day = $startDay; $day -le $endDay; $day++) {
        $dayNum = "{0:D2}" -f $day
        $filename = "wls_day-$dayNum.bz2"
        $url = "$baseUrl/wls/$filename"
        $outPath = Join-Path $hostEventsDir $filename

        Start-LANLDownload -Url $url -OutPath $outPath -Description "WLS Day $day"

        # Small delay between downloads
        Start-Sleep -Milliseconds 500
    }
    Write-Host ""
}

# Download Netflow files
if (-not $SkipNetflow) {
    Write-Host "Downloading Netflow files..." -ForegroundColor Cyan
    Write-Host "---------------------------------------------------" -ForegroundColor Cyan

    for ($day = $startDay; $day -le $endDay; $day++) {
        $dayNum = "{0:D2}" -f $day
        $filename = "netflow_day-$dayNum.bz2"
        $url = "$baseUrl/netflow/$filename"
        $outPath = Join-Path $netflowDir $filename

        Start-LANLDownload -Url $url -OutPath $outPath -Description "Netflow Day $day"

        # Small delay between downloads
        Start-Sleep -Milliseconds 500
    }
    Write-Host ""
}

# Summary
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Download Summary" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Total Files:     $($stats.TotalFiles)"
Write-Host "Downloaded:      $($stats.Downloaded)" -ForegroundColor Green
Write-Host "Skipped:         $($stats.Skipped)" -ForegroundColor Gray
Write-Host "Failed:          $($stats.Failed)" -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Gray" })
Write-Host "Total Size:      $([math]::Round($stats.TotalBytes/1GB, 2)) GB" -ForegroundColor Cyan

# List failed files
if ($stats.Failed -gt 0) {
    Write-Host ""
    Write-Host "Some files failed to download. You can retry with:" -ForegroundColor Yellow
    Write-Host "  .\download_lanl_wls_netflow.ps1 -Resume" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Download complete!" -ForegroundColor Green

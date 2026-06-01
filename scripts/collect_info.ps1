#Requires -Version 5.1
# Collects device info needed for a JoyConDroidCompanion bug report.
# Restarts Bluetooth at the end to capture the jcdshim logcat.
$ErrorActionPreference = 'Stop'

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    Write-Error "adb not found in PATH"
    exit 1
}

$Manufacturer = (& adb shell getprop ro.product.manufacturer 2>$null) -replace "`r|`n", ""
$Model        = (& adb shell getprop ro.product.model        2>$null) -replace "`r|`n", ""

if (-not $Manufacturer -or -not $Model) {
    Write-Error "No device connected"
    exit 1
}

Write-Host "Collecting device info ..."

$Android     = (& adb shell getprop ro.build.version.release          2>$null) -replace "`r|`n", ""
$Fingerprint = (& adb shell getprop ro.build.fingerprint               2>$null) -replace "`r|`n", ""
$Security    = (& adb shell getprop ro.build.version.security_patch    2>$null) -replace "`r|`n", ""
$SocMfr      = (& adb shell getprop ro.soc.manufacturer                2>$null) -replace "`r|`n", ""
$SocModel    = (& adb shell getprop ro.soc.model                       2>$null) -replace "`r|`n", ""
$Rom         = (& adb shell getprop ro.build.display.id                2>$null) -replace "`r|`n", ""
$Selinux     = (& adb shell getenforce                                 2>$null) -replace "`r|`n", ""

$Magisk = try {
    (& adb shell magisk -v 2>$null) -replace "`r|`n", ""
} catch { "" }
if (-not $Magisk) { $Magisk = "(not found)" }

$BtLib = (& adb shell `
    "ls /apex/com.android.btservices/lib64/libbluetooth_jni.so /vendor/lib64/libbluetooth_qti.so /system/lib64/libbluetooth_qti.so /system/lib64/libbluetooth.so 2>/dev/null" `
    2>$null) -replace "`r", ""

$JcdVer = try {
    (& adb shell "dumpsys package com.rdapps.gamepad 2>/dev/null | grep versionName | cut -d= -f2" 2>$null) -replace "`r|`n", ""
} catch { "" }
if (-not $JcdVer) { $JcdVer = "(not installed)" }

Write-Host "Restarting Bluetooth to capture jcdshim logcat (~15 seconds) ..."
$null = & adb logcat -c 2>$null
& adb shell "am force-stop com.android.bluetooth; sleep 3; svc bluetooth enable; sleep 8"
$Logcat = (& adb logcat -s jcdshim libc crash_dump64 -d 2>$null) -replace "`r", ""

Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════"
Write-Host "  JoyConDroidCompanion – Issue Info Collector"
Write-Host "  Paste each value into the corresponding GitHub issue field."
Write-Host "══════════════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "Issue title:            [$Manufacturer $Model] <short description>"
Write-Host ""
Write-Host "Device:                 $Manufacturer $Model"
Write-Host "Android version:        $Android"
Write-Host "Build fingerprint:      $Fingerprint"
Write-Host "Security patch date:    $Security"
Write-Host "SoC:                    $SocMfr $SocModel"
Write-Host "ROM:                    $Rom"
Write-Host "Magisk version:         $Magisk"
("Bluetooth library path: " + ($BtLib -join "`n")) -split "`n" | ForEach-Object { Write-Host "  $_" }
Write-Host "SELinux mode:           $Selinux"
Write-Host "Joy-Con Droid version:  $JcdVer"
Write-Host ""
Write-Host "─────────────────────── Logs ───────────────────────"
$Logcat | ForEach-Object { Write-Host $_ }
Write-Host "────────────────────────────────────────────────────"
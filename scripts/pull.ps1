#Requires -Version 5.1
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

# _orig.so variants come first: when the module is already installed the
# bind-mount overlays the canonical name with the shim, but leaves the
# renamed original accessible as *_orig.so in the same directory.
$Candidates = @(
    "/apex/com.android.btservices/lib64/libbluetooth_jni_orig.so",
    "/apex/com.android.btservices/lib64/libbluetooth_jni.so",
    "/vendor/lib64/libbluetooth_qti_orig.so",
    "/vendor/lib64/libbluetooth_qti.so",
    "/system/lib64/libbluetooth_qti_orig.so",
    "/system/lib64/libbluetooth_qti.so",
    "/system/system_ext/lib64/libbluetooth_qti_orig.so",
    "/system/system_ext/lib64/libbluetooth_qti.so",
    "/system/lib64/libbluetooth_orig.so",
    "/system/lib64/libbluetooth.so"
)

$RemotePath = $null
foreach ($cand in $Candidates) {
    $result = (& adb shell "[ -f '$cand' ] && echo yes || echo no" 2>$null) -replace "`r|`n", ""
    if ($result -eq "yes") { $RemotePath = $cand; break }
}

if (-not $RemotePath) {
    Write-Error "No supported libbluetooth*.so found on device"
    exit 1
}

# Always save under the canonical name (strip _orig suffix if present).
$LibName = (Split-Path $RemotePath -Leaf) -replace '_orig\.so$', '.so'
$OutPath = Join-Path $PSScriptRoot "libs\$Manufacturer\$Model\$LibName"
New-Item -ItemType Directory -Force -Path (Split-Path $OutPath) | Out-Null

Write-Host "Device: $Manufacturer $Model"
Write-Host "Remote: $RemotePath"
Write-Host "Local:  $OutPath"
& adb pull $RemotePath $OutPath
$ErrorActionPreference = 'Stop'
$DefaultRepo = 'kiankan/Kan-Widget'
$EnteredRepo = Read-Host "GitHub repository [$DefaultRepo]"
$Repo = if ([string]::IsNullOrWhiteSpace($EnteredRepo)) { $DefaultRepo } else { $EnteredRepo.Trim() }

if ($Repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw 'Invalid repository. Enter it as username/repository.'
}

$Url = "https://github.com/$Repo/releases/latest/download/KanWidget-Windows.zip"
$Temp = Join-Path $env:TEMP 'KanWidget-Install'
$Dest = Join-Path $env:LOCALAPPDATA 'Programs\KanWidget'
$ZipPath = Join-Path $Temp 'KanWidget-Windows.zip'

Write-Host "Downloading the latest Windows build from GitHub..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
Invoke-WebRequest -Uri $Url -OutFile $ZipPath

if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Expand-Archive -Path $ZipPath -DestinationPath $Dest -Force

$Exe = Get-ChildItem $Dest -Filter 'KanWidget.exe' -Recurse | Select-Object -First 1
if (-not $Exe) { throw 'KanWidget.exe was not found in the downloaded package.' }

$ShortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Kan Widget.lnk'
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Exe.FullName
$Shortcut.WorkingDirectory = $Exe.DirectoryName
$Shortcut.Save()

Write-Host "Installed. Desktop shortcut: $ShortcutPath" -ForegroundColor Green

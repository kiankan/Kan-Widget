$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = 'kiankan/Kan-Widget'
$ApiHeaders = @{
    'Accept' = 'application/vnd.github+json'
    'User-Agent' = 'KanWidget-Installer'
}

function Write-Step([string]$Message) {
    Write-Host "[Kan Widget] $Message" -ForegroundColor Cyan
}

try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'Kan Widget can only be installed on Windows 10/11.'
    }

    Write-Step 'Checking the latest published version...'
    $ReleaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
    $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers $ApiHeaders -Method Get

    $ReleaseVersion = $null
    if ($Release.tag_name -match '^v(?<version>\d+\.\d+\.\d+)$') {
        $ReleaseVersion = [version]$Matches['version']
    }
    if ($null -eq $ReleaseVersion -or $ReleaseVersion -lt [version]'0.1.1') {
        throw "The latest published release is outdated. The fixed v0.1.1 build has not been published yet; installation was cancelled to avoid reinstalling the known-buggy v0.1.0."
    }

    $ZipAsset = $Release.assets | Where-Object { $_.name -eq 'KanWidget-Windows.zip' } | Select-Object -First 1
    $HashAsset = $Release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
    if (-not $ZipAsset -or -not $HashAsset) {
        throw "The latest GitHub Release does not contain the installer files. Check https://github.com/$Repo/actions."
    }

    $WorkDir = Join-Path $env:TEMP ("KanWidget-" + [guid]::NewGuid().ToString('N'))
    $ZipPath = Join-Path $WorkDir 'KanWidget-Windows.zip'
    $HashPath = Join-Path $WorkDir 'SHA256SUMS.txt'
    $ExtractPath = Join-Path $WorkDir 'extracted'
    $InstallPath = Join-Path $env:LOCALAPPDATA 'Programs\KanWidget'

    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    Write-Step "Downloading version $($Release.tag_name)..."
    Invoke-WebRequest -Uri $ZipAsset.browser_download_url -OutFile $ZipPath -Headers $ApiHeaders -UseBasicParsing
    Invoke-WebRequest -Uri $HashAsset.browser_download_url -OutFile $HashPath -Headers $ApiHeaders -UseBasicParsing

    $ExpectedHashLine = Get-Content -LiteralPath $HashPath | Where-Object { $_ -match 'KanWidget-Windows\.zip$' } | Select-Object -First 1
    if (-not $ExpectedHashLine) {
        throw 'The SHA256 checksum was not found in the release.'
    }
    $ExpectedHash = ($ExpectedHashLine -split '\s+')[0].ToUpperInvariant()
    $ActualHash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($ExpectedHash -ne $ActualHash) {
        throw 'The downloaded package failed SHA256 verification. Installation was cancelled.'
    }

    Write-Step 'Verifying and extracting the package...'
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $ExtractPath -Force
    $Exe = Get-ChildItem -LiteralPath $ExtractPath -Filter 'KanWidget.exe' -File -Recurse | Select-Object -First 1
    if (-not $Exe) {
        throw 'KanWidget.exe was not found in the release archive.'
    }

    $Running = Get-Process -Name 'KanWidget' -ErrorAction SilentlyContinue
    if ($Running) {
        throw 'Kan Widget is currently running. Close it and run the installation command again.'
    }

    if (Test-Path -LiteralPath $InstallPath) {
        Remove-Item -LiteralPath $InstallPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Copy-Item -Path (Join-Path $Exe.DirectoryName '*') -Destination $InstallPath -Recurse -Force

    $InstalledExe = Join-Path $InstallPath 'KanWidget.exe'
    if (-not (Test-Path -LiteralPath $InstalledExe)) {
        throw 'Installation files were copied, but KanWidget.exe is missing.'
    }

    $Shell = New-Object -ComObject WScript.Shell
    $DesktopShortcut = $Shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Kan Widget.lnk'))
    $DesktopShortcut.TargetPath = $InstalledExe
    $DesktopShortcut.WorkingDirectory = $InstallPath
    $DesktopShortcut.IconLocation = "$InstalledExe,0"
    $DesktopShortcut.Save()

    $StartMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Kan Widget'
    New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null
    $StartShortcut = $Shell.CreateShortcut((Join-Path $StartMenuDir 'Kan Widget.lnk'))
    $StartShortcut.TargetPath = $InstalledExe
    $StartShortcut.WorkingDirectory = $InstallPath
    $StartShortcut.IconLocation = "$InstalledExe,0"
    $StartShortcut.Save()

    Write-Step "Kan Widget $($Release.tag_name) was installed successfully."
    Write-Step 'Launching Kan Widget...'
    Start-Process -FilePath $InstalledExe -WorkingDirectory $InstallPath
}
catch {
    Write-Host "[Kan Widget] Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    if ($WorkDir -and (Test-Path -LiteralPath $WorkDir)) {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

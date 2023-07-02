# Array of all tools which need to be installed
$tools = @{
    "Sysinternals.zip"="https://download.sysinternals.com/files/SysinternalsSuite.zip";
    "Ghidra.zip"="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.1_build/ghidra_10.3.1_PUBLIC_20230614.zip";
    "WinSpy.zip"="https://github.com/strobejb/winspy/releases/download/v1.8.4/WinSpy_Release_x64.zip";
    "DnSpy-64.zip"="https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win64.zip";
    "DnSpy-32.zip"="https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win32.zip";
    "jd-gui.zip"="https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-windows-1.6.6.zip";
    "ExplorerSuite.exe"="https://ntcore.com/files/ExplorerSuite.exe";
    "Get-PESecurity.ps1"="https://github.com/NetSPI/PESecurity/blob/master/Get-PESecurity.psm1";
    "Spartacus.zip"="https://github.com/Accenture/Spartacus/releases/download/v2.0.0/Spartacus-v2.0.0-x64.zip";
    "BurpSuite.exe"="https://portswigger-cdn.net/burp/releases/download?product=pro&version=2023.6.2&type=WindowsX64";
    "Wireshark.exe"="https://2.na.dl.wireshark.org/win64/Wireshark-win64-4.0.6.exe";
}

# Install directory
$installDirectory = "$home\Documents\Pentest-Directory"

function New-Software ([String] $SoftwareName, [String] $Filename) {
    # Var to determine if a uncompressed version of the app exists already in the directory to skip the download
    $newFilename = $Filename -replace ".{4}$"

    # Download the file from it's source
    try {
        if ((Test-Path -Path "$installDirectory\Tools\$Filename") -or (Test-Path -Path "$installDirectory\Tools\$newFilename")) {
            Write-Host "[*] Skipping $Filename. Already exists in local directory." -ForegroundColor Yellow
        } else {
            Invoke-WebRequest -Uri $SoftwareName -OutFile "$installDirectory\Tools\$Filename"
            Write-Host "[+] $Filename downloaded and in the tool directory." -ForegroundColor Green

            # Then check if the file needs to be de-compressed ie, it's a zip file
            try {
                if (Test-Path -Path $installDirectory\Tools\$newFilename) {
                    Write-Host "[*] Skipping $Filename. Is already decompressed or does not need decompressing."
                } else {
                    if ($Filename -match '.zip$') {
                        # Create new dir name
                        Expand-Archive $installDirectory\Tools\$Filename -DestinationPath $installDirectory\Tools\$newFilename
                        # Once the above is complete remove the zip file
                        try {
                            Remove-Item -Path "$installDirectory\Tools\$Filename"
                            Write-Host "[+] $Filename cleaned up" -ForegroundColor Green
                         } catch {
                            Write-Host "[-] There was an error cleaning up $Filename" -ForegroundColor Red
                         }
                    }
                }
            } catch {
                Write-Host "[-] There was an error decompressing $Filename" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "[-] There was an error downloading $Filename" -ForegroundColor Red
    }
}

function Install-Software {
    # Try to create folder structure if not throw an error, likely due to perms
    try {
        # Set-up the folder structure
        if (Test-Path -Path "$installDirectory") {
            Write-Host '[*] Pentest-Directory already exists, skipping creation.' -ForegroundColor Yellow
            # Check if Output folder is created, if not create it
            if (Test-Path -Path "$installDirectory\Output") {
                Write-Host "[*] Output sub-directory already exists, skipping creation." -ForegroundColor Yellow
            } else {
                New-Item -Path "$installDirectory\Output" -ItemType Directory # For test output
                Write-Host "[+] Output Directory Created" -ForegroundColor Green
            }
            # Check if Tools folder is created, if not create it
            if (Test-Path -Path "$installDirectory\Tools") {
                Write-Host "[*] Tools sub-directory already exists, skipping creation." -ForegroundColor Yellow
            } else {
                New-Item -Path "$installDirectory\Tools" -ItemType Directory # For tools to be installed
                Write-Host "[+] Tools Directory Created" -ForegroundColor Green
            }
        } else {
            # Create a parent directory, then some sub directories for output and tools
            New-Item -Path "$installDirectory" -ItemType Directory # Parent
            New-Item -Path "$installDirectory\Output" -ItemType Directory # For test output
            New-Item -Path "$installDirectory\Tools" -ItemType Directory # For tools to be installed
            Write-Host "[+] Folder Structure Created" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] There was an error creating the files. Ensure you have permissions to write to the following path and re-run this tool: $home" -ForegroundColor Red
    }

    # Install all required software - see guide for information as to each of their purposes
    foreach ($software in $tools.Keys) {
        try {
            New-Software -SoftwareName $tools[$software] -Filename $software
        } catch {
            Write-Host "[-] Error installing $software from remote source: $tools[$software]" -ForegroundColor Red
       }
    }

    # Open Explorer when finished
    explorer.exe $installDirectory
}

Install-Software
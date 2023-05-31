function Get-LatestVulnerableDrivers {
    Write-Output "[*] Getting latest loldriver.io info..."
    $global:lolDrivers = (New-Object System.Net.WebClient).DownloadString("https://www.loldrivers.io/api/drivers.json") | ConvertFrom-Json
}

function Get-RunningServices {
    $global:runningServices = gwmi win32_systemdriver| where {$_.State -eq "Running"} | select pathname
}

function Find-VulnerableDrivers{

    if($global:lolDrivers -eq $null){
        Get-LatestVulnerableDrivers
    }
    if($global:runningServices -eq $null){
        Get-RunningServices
    }

    Write-Output "[*] Enumerating drives..."
    $drives =  Get-PSDrive | where {$_.Provider.ToString() -eq 'Microsoft.PowerShell.Core\FileSystem' } | select Root

    foreach($drive in $drives){
        Write-output "[*] Checking $($drive.Root) ..."
        $drivers = Get-ChildItem -Path $drive.Root -Recurse -Include "*.sys" -ErrorAction SilentlyContinue
        Write-output("[*] Checking $($drivers.Count) drivers against loldrivers.io")
        foreach($driver in $drivers){
            $hash = (Get-FileHash -Path $driver.FullName).HASH.ToString().ToLower()
            if($global:lolDrivers.KnownVulnerableSamples.SHA256.Contains($hash)){
                $thisLolDriver = $global:lolDrivers | where {if($_.KnownVulnerableSamples.SHA256 -ne $null) {$_.KnownVulnerableSamples.SHA256.Contains($hash)}} | where {$_.KnownVulnerableSamples.FileName.Trim() -ne ''}
                $thisLolDriver = ($thisLolDriver.KnownVulnerableSamples.FileName | Sort-Object | Get-Unique) -join '/'
                Write-Output("[!] Vulnerable driver found on disk: $($driver.FullName) ($($hash) -> $($thisLolDriver))")
                if($global:runningServices.Contains($driver.FullName)){
                    $driverServices = gwmi win32_systemdriver| where {$_.State -eq "Running"} | where {if($_.PathName -ne $null) {$_.PathName.Contains($driver.FullName)}} | select Name
                    $driverServices = $driverServices -join '/'
                    Write-Output("[!] `tVulnerable driver is running! - Service(s): $driverServices")
                }
            }
        }
    }
}

Find-VulnerableDrivers

function Get-LatestVulnerableDrivers {
    Write-Output "Getting latest loldriver.io info..."
    $global:lolDrivers = (New-Object System.Net.WebClient).DownloadString("https://www.loldrivers.io/api/drivers.json") | ConvertFrom-Json
}

function Find-VulnerableDrivers{

    if($global:lolDrivers -eq $null){
        Get-LatestVulnerableDrivers
    }

    Write-Output "Enumerating drives..."
    $drives =  Get-PSDrive | where {$_.Provider.ToString() -eq 'Microsoft.PowerShell.Core\FileSystem' } | select Root

    foreach($drive in $drives){
        Write-output "Checking $($drive.Root) ..."
        $drivers = Get-ChildItem -Path $drive.Root -Recurse -Include "*.sys" -ErrorAction SilentlyContinue
        Write-output("Checking $($drivers.Count) drivers against loldrivers.io")
        foreach($driver in $drivers){
            $hash = Get-FileHash -Path $driver.FullName
            if($global:lolDrivers.KnownVulnerableSamples.SHA256.Contains($hash.HASH.ToString().ToLower())){
                Write-Output("$($driver.FullName) is vulnerable with a matching SHA256 hash of $($hash.HASH)")
            }
        }
    }

}

Find-VulnerableDrivers

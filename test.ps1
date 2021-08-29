how to bypass the execution polocy?


Write-Host "Installing Brave Browser"
winget install BraveSoftware.BraveBrowser | Out-Host
if($?) { Write-Host "Installed Brave Browser"}
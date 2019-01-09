Start-Transcript -Path '.\\Add-BdeHdCfg.Log'
if (((Get-WindowsEdition -Online).Edition -match '^Server.+Cor$') -and ($bdehdcfgURI.length -gt 0)) {
    #see if bdehdcfg is already present
    if (-not (Test-Path ($env:windir + '\\system32\\BdeHdCfg.exe')) -or -not (Test-Path ($env:windir + '\\system32\\BdeHdCfgLib.dll'))) {
        $bdehdcfgURI -imatch '.+/(.+)$' | Out-Null
        $bdehdcfgZIP = $env:TEMP + '\\' + $matches[1]
        Write-Host (get-date -DisplayHint Time) adding bdehdcfg to Windows Server Core to support Azure Disk Encryption
        Write-Host (get-date -DisplayHint Time) download bdehdcfg from $bdehdcfgURI to $bdehdcfgZIP and expand to $env:windir
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest $bdehdcfgURI -Out $bdehdcfgZIP
        try {
            Expand-Archive -LiteralPath $bdehdcfgZIP -DestinationPath $env:windir -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host (get-date -DisplayHint Time) failed to expand $bdehdcfgZIP to $env:windir / most likely the files already exist
        }
        # Removing temp files
        Remove-Item $bdehdcfgZIP -Force
    }
}
Stop-Transcript

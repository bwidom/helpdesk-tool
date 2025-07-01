function Start-Shadow {
    param(
        [string] $ComputerName
    )

    $alAvailableSessions = [System.Collections.ArrayList]::new()
    
    $sessions = (qwinsta /server $ComputerName).split("`n")

    for($i = 1; $i -lt $sessions.count; $i++){
        if($sessions[$i].Substring(19,1).Trim() -ne [string]::Empty){
            [void] $alAvailableSessions.Add([pscustomObject]@{
                sessionName = $sessions[$i].Substring(19,20).Trim()
                sessionID = $sessions[$i].Substring(41,5).Trim()
            })
        }
    }

    Write-Host "Displaying available sessions"
    Write-Host "-----------------------------"

    for($i = 0; $i -lt $alAvailableSessions.Count; $i++){
        Write-Host "$($i+1)           $($alAvailableSessions[$i].sessionName)"
    }

    Write-Host "`n`n`nSelect the session to shadow"
    $i = Read-Host
   
    Mstsc.exe /shadow:($alAvailableSessions[$i - 1].sessionID) /v:$ComputerName



}

Start-Shadow -ComputerName localhost

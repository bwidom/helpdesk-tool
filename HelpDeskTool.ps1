Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
$WebRequest = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bwidom/helpdesk-tool/refs/heads/main/MainWindow.xaml"
[xml]$XAML = $WebRequest.Content
#[xml]$XAML = Get-Content 'MainWindow.xaml'

$XAML.Window.RemoveAttribute('x:Class')
$XAML.Window.RemoveAttribute('mc:Ignorable')
$XAMLReader = New-Object System.Xml.XmlNodeReader $XAML
$MainWindow = [Windows.Markup.XamlReader]::Load($XAMLReader)
$XAML.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $MainWindow.FindName($_.Name)}

$dgAccountInfo = $MainWindow.FindName("dgAccountInfo")
$cbSearchCriteria = $MainWindow.FindName("cbSearchCriteria")
$tbSearchUser = $MainWindow.FindName("tbSearchUser")
$lEmployeeID = $MainWindow.FindName("lEmployeeID")
$lSAMAccountName = $MainWindow.FindName("lSAMAccountName")
$tbComputerSearch = $MainWindow.FindName("tbComputerSearch")
$lbSessions = $MainWindow.FindName("lbSessions")
$tbComputerName = $MainWindow.FindName('tbComputerName')
$tbIPAddress = $MainWindow.FindName('tbIPAddress')
$tbFreeDiskSpace = $MainWindow.FindName('tbFreeDiskSpace')
$tbMemoryUsage = $MainWindow.FindName('tbMemoryUsage')
$tbLastBootTime = $MainWindow.FindName('tbLastBootTime')
$iDisabledIcon = $MainWindow.FindName('iDisabledIcon')

$tbSearchUser.Focus() | Out-Null

$dataTable = New-Object System.Data.DataTable

[void]$dataTable.Columns.Add("DC Name", [string])
[void]$dataTable.Columns.Add("LastBadPassword", [string])
[void]$dataTable.Columns.Add("PasswordLastSet", [string])
[void]$dataTable.Columns.Add("PasswordExpirationDate", [string])
[void]$dataTable.Columns.Add("LockedOut", [string])
[void]$dataTable.Columns.Add("BadLogonCount", [int])

#Properties for Get-ADUser command
$properties = @("LastBadPasswordAttempt", "PasswordLastSet", "msDS-UserPasswordExpiryTimeComputed", "BadLogonCount", "LockedOut", "EmployeeID", "SAMAccountName")

$dgAccountInfo.ItemsSource = $dataTable.DefaultView

$dcs = @(Get-ADDomainController -Filter * | Sort-Object -Property Name)
$rows = [Object[]]::new($dcs.Count)
$domainDistinguishedName = (Get-ADDomain).DistinguishedName


for($i=0; $i -lt $dcs.Count; $i++){
    $rows[$i] = $dataTable.NewRow()
    $dataTable.Rows.Add($rows[$i])
}

#Set rows on data grid. 
function Set-Rows{
    param(
        [Parameter(Position=0)]
        [int]$RowIndex,
        [Parameter(Position=1)]
        [string]$LastBadPassword=[string]::Empty,
        [Parameter(Position=2)]
        [string]$PasswordLastSet=[string]::Empty,
        [Parameter(Position=3)]
        [string]$PasswordExpirationDate=[string]::Empty,
        [Parameter(Position=4)]
        [string]$LockedOut=[string]::Empty,
        [Parameter(Position=5)]
        $BadLogonCount=[DBNull]::Value,
        [Parameter(Position=6)]
        [string]$DCName = [string]::Empty
    )
    $rows[$RowIndex]["LastBadPassword"] = $LastBadPassword
    $rows[$RowIndex]["PasswordLastSet"] = $PasswordLastSet
    $rows[$RowIndex]["PasswordExpirationDate"] = $PasswordExpirationDate
    $rows[$RowIndex]["LockedOut"] = $LockedOut
    $rows[$RowIndex]["BadLogonCount"] = $BadLogonCount
    $rows[$RowIndex]["DC Name"] = $DCName
    
}


function Search-User{
    $lEmployeeID.Text = "Collecting data..."
    $lSAMAccountName.Text = ""
    $iDisabledIcon.Visibility="Hidden"
    #[System.Windows.Forms.Application]::DoEvents()
    switch($cbSearchCriteria.SelectedIndex){
        0{
            $filter = "(EmployeeID -eq '$($tbSearchUser.Text)') "
        }
        1{
            $x = "*"+$tbSearchUser.Text+"*"
            $filter = "Name -like '$x' -OR SAMAccountName -like '$x'"          
        }
    }
    
    #Get count of users who match criteria. If more than one, diplay matching users.
    $countUser = @(Get-ADUser -Filter $filter -SearchBase $domainDistinguishedName)

    if($countUser.Count -eq 1){
        for($i = 0; $i -lt $dcs.Count; $i++){ 
            #if(Test-Connection ($dcs[$i]).Name -Count 1 -Quiet){
                $userInfoOnServer = @(Get-ADUser -Server $dcs[$i] -Filter $filter -Properties $properties -SearchBase $domainDistinguishedName)
                Set-Rows $i `
                    $(if($userInfoOnServer.LastBadPasswordAttempt){$userInfoOnServer.LastBadPasswordAttempt}else{'None'}) `
                    $(if($userInfoOnServer.PasswordLastSet){$userInfoOnServer.PasswordLastSet}else{"Change Password"}) `
                    $(if($userInfoOnServer.PasswordLastSet){[datetime]::FromFileTime($userInfoOnServer.'msDS-UserPasswordExpiryTimeComputed')}else{"N/A"}) `
                    $(if((Get-ADUser -Filter $filter -Properties * | Select-Object -ExpandProperty lockoutTime) -gt 0){"Locked"}else{"Unlocked"}) `
                    $(if($userInfoOnServer.BadLogonCount){$userInfoOnServer.BadLogonCount}else{0}) `
                    $($dcs[$i].Name)
            #}else{
            #    $rows[$i]["DC Name"] = $dcs[$i].Name
            #    $rows[$i]["LockedOut"] = "DC Unavailable"
            #}
        }
        if($countUser[0].Enabled){$iDisabledIcon.Visibility='Hidden'}else{$iDisabledIcon.Visibility='Visible'}
        $lEmployeeID.Text = $userInfoOnServer.EmployeeID
        $lSAMAccountName.Text = $userInfoOnServer.SAMAccountName
    }elseif($countUser.Count -eq 0){
        for($i = 0; $i -lt $dcs.Count; $i++){       
            Set-Rows -RowIndex $i      
        }
        $lEmployeeID.Text = "User Not Found"
        $lSAMAccountName.Text = ""
    }elseif($countUser.Count -gt 1){
        Create-SelectUserWindow
       
    }
}

function Unlock-User{
    #Check if a user is selected.
    if($lSAMAccountName.Text){
        foreach($dc in $dcs){
            #if(Test-Connection ($dc).Name -Count 1 -Quiet){
                Unlock-ADAccount -Identity $lSAMAccountName.Text -Server $dc
            #}
        }
        Search-User
    }else{
        Write-Host "No User Selected"
    }
}


function Create-PasswordWindow{
    if($lSAMAccountName.Text){
        $WebRequest = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bwidom/helpdesk-tool/refs/heads/main/ChangePasswordWindow.xaml"
        [xml]$XAML = $WebRequest.Content
        #[xml]$XAML = Get-Content 'ChangePasswordWindow.xaml'

        $XAML.Window.RemoveAttribute('x:Class')
        $XAML.Window.RemoveAttribute('mc:Ignorable')
        $XAMLReader = New-Object System.Xml.XmlNodeReader $XAML
        $ChangePasswordWindow = [Windows.Markup.XamlReader]::Load($XAMLReader)
        $XAML.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $ChangePasswordWindow.FindName($_.Name)}
        $ChangePasswordWindow.Owner = $MainWindow
        $ChangePasswordWindow.WindowStartupLocation = 'CenterOwner'      

        $lChangePasswordPrompt = $ChangePasswordWindow.FindName("lChangePasswordPrompt")
        $lChangePasswordPrompt.Content = "Change " + $lSAMAccountName.Text + "'s password to:"

        if(($lEmployeeID.Text.length -lt 2)){
            $Digits = '00'
        }else{
            $digits = $lEmployeeID.Text.Substring($lEmployeeID.Text.Length - 2)
        }
        $password = "Changepasswordnow" + $Digits
        $tbNewPassword = $ChangePasswordWindow.FindName("tbNewPassword")
        $tbNewPassword.Text = $password

        function Change-UserPassword{
            Write-Host "Changing Password of $($lSAMAccountName.Text) to $($tbNewPassword.Text)"
            $u = Set-ADAccountPassword -Identity $lSAMAccountName.Text -NewPassword (ConvertTo-SecureString -AsPlainText $tbNewPassword.Text -Force) -PassThru           
            Set-ADUser -Identity $lSAMAccountName.Text -ChangePasswordAtLogon $true
            [System.Windows.Forms.MessageBox]::Show("Password Changed")
            Write-Host "$(($u.Name)) password changed to $($tbNewPassword.Text). Password must change at login"
            $ChangePasswordWindow.Close()
        }

        $bConfirm = $ChangePasswordWindow.FindName("bConfirm")
        $bConfirm.Add_Click({Change-UserPassword})

        $bCancel = $ChangePasswordWindow.FindName("bCancel")
        $bCancel.Add_Click({$ChangePasswordWindow.Close()})

        $ChangePasswordWindow.ShowDialog() | Out-Null
    
    }
}

function Create-SelectUserWindow{

    $WebRequest = Invoke-WebRequest "https://raw.githubusercontent.com/bwidom/helpdesk-tool/refs/heads/main/SelectUserWindow.xaml"
    [xml]$XAML = $WebRequest.Content
    #[xml]$XAML = Get-Content 'SelectUserWindow.xaml'

    $XAML.Window.RemoveAttribute('x:Class')
    $XAML.Window.RemoveAttribute('mc:Ignorable')
    $XAMLReader = New-Object System.Xml.XmlNodeReader $XAML
    $SelectUserWindow = [Windows.Markup.XamlReader]::Load($XAMLReader)
    $XAML.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $ChangePasswordWindow.FindName($_.Name)}
    $SelectUserWindow.Owner = $MainWindow
    $SelectUserWindow.WindowStartupLocation = 'CenterOwner'

    $lbUsers = $SelectUserWindow.FindName('lbUsers')
    $userInfo = $userInfoOnServer = @(Get-ADUser -Filter $filter)
    foreach($u in $userInfo){
        $lbUsers.AddChild($u.SAMAccountName)
    }

    $bSelectUser = $SelectUserWindow.FindName('bSelectUser')
    $bSelectUser.Add_Click({Select-User})

    $bCancel = $SelectUserWindow.FindName('bCancel')
    $bCancel.Add_Click({
        $SelectUserWindow.Close()
        $lEmployeeID.Text = ''
        $lSAMAccountName.Text = ''
    })

    #Select user from window displaying list of users retrieved from Search-User command. When user selected, their
    #information is filled in the main window.
    function Select-User{
        $lEmployeeID.Text = "Collecting data..."
        $lSAMAccountName.Text = ""
        $user = $lbUsers.SelectedItem
        $iDisabledIcon.Visibility="Hidden"
        for($i = 0; $i -lt $dcs.Count; $i++){ 
            #if(Test-Connection ($dcs[$i]).Name -Count 1 -Quiet){
                $userInfoOnServer = @(Get-ADUser $user -Server $dcs[$i] -Properties $properties)
                Set-Rows $i `
                    $(if($userInfoOnServer.LastBadPasswordAttempt){$userInfoOnServer.LastBadPasswordAttempt}else{'None'}) `
                    $(if($userInfoOnServer.PasswordLastSet){$userInfoOnServer.PasswordLastSet}else{"Change Password"}) `
                    $(if($userInfoOnServer.PasswordLastSet){[datetime]::FromFileTime($userInfoOnServer.'msDS-UserPasswordExpiryTimeComputed')}else{"N/A"}) `
                    $(if((Get-ADUser -Filter $filter -Properties * | Select-Object -ExpandProperty lockoutTime) -gt 0){"Locked"}else{"Unlocked"}) `
                    $(if($userInfoOnServer.BadLogonCount){$userInfoOnServer.BadLogonCount}else{0}) `
                    $($dcs[$i].Name)
            #}else{
            #    $rows[$i]["DC Name"] = $dcs[$i].Name
            #    $rows[$i]["LockedOut"] = "DC Unavailable"
            #}
        }
        if($countUser[0].Enabled){$iDisabledIcon.Visibility='Hidden'}else{$iDisabledIcon.Visibility='Visible'}
        $lEmployeeID.Text = $userInfoOnServer.EmployeeID
        $lSAMAccountName.Text = $userInfoOnServer.SAMAccountName
        $SelectUserWindow.Close()
    }

    
    $SelectUserWindow.ShowDialog() | Out-Null
}

function Clear-Window{
    for($i = 0; $i -lt $dcs.Count; $i++){             
        $rows[$i]["LastBadPassword"] = [string]::Empty
        $rows[$i]["PasswordLastSet"] = [string]::Empty
        $rows[$i]["PasswordExpirationDate"] = [string]::Empty
        $rows[$i]["LockedOut"] = [string]::Empty
        $rows[$i]["BadLogonCount"] = [DBNull]::Value
        $rows[$i]["DC Name"] = [string]::Empty
    }
    $lEmployeeID.Text = "User Not Found"
    $lSAMAccountName.Text = ""
}

function Search-Computer{    
    $lbSessions.Items.Clear()
    $tbComputerName.Text = ''
    $tbIPAddress.Text =  ''
    $tbFreeDiskSpace.Text = ''
    $tbMemoryUsage.Text = ''
    $tbLastBootTime.Text = ''
    try{
        if($tbComputerSearch.Text){
            $computerName = @(Get-ADComputer -Identity $tbComputerSearch.Text)

            $alAvailableSessions = [System.Collections.ArrayList]::new()
            
            #Get sessions on computer from native Windows command qwinsta as string
            #Parse name, id and state of the active sessions from the string by getting 
            #index of where each of these fields are on each row.
            $sessions = (qwinsta /server $tbComputerSearch.Text).split("`n")
            $usernameIndex = $sessions[0].IndexOf('USERNAME')
            $IDIndex = $sessions[0].IndexOf('ID') - 2
            $stateIndex = $sessions[0].IndexOf('STATE')

            for($i = 1; $i -lt $sessions.count; $i++){
                if($sessions[$i].Substring($usernameIndex,1).Trim() -ne [string]::Empty){
                    [void] $alAvailableSessions.Add([pscustomObject]@{
                        sessionName = $sessions[$i].Substring($usernameIndex,20).Trim()
                        sessionID = $sessions[$i].Substring($IDIndex,5).Trim()
                        sessionState = $sessions[$i].Substring($stateIndex,6).Trim()
                    })
                }
            }

            foreach($session in $alAvailableSessions){
                $lbSessions.AddChild("$($session.sessionName)                  $($session.sessionID)                  $($session.sessionState)")
            }
            $tbComputerName.Text = $computerName.Name
            #$tbIPAddress.Text =  Invoke-Command -ComputerName $computerName.Name -ScriptBlock { Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notmatch 'Loopback|Bluetooth'} | Select-Object -ExpandProperty IPAddress }
            $tbFreeDiskSpace.Text = "$((Get-WMIObject -ComputerName $computerName.Name -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq 'C:'} | Select-Object  @{Name="FreeSpacePercent"; Expression={[Math]::Round(($_.FreeSpace / $_.Size) * 100)}}).FreeSpacePercent)%"
            $tbMemoryUsage.Text = "$((Get-Counter -ComputerName $computerName.Name -Counter '\Memory\Available MBytes').CounterSamples.CookedValue) MB"
            $tbLastBootTime.Text = [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject -ComputerName $computerName.Name -Class Win32_OperatingSystem).LastBootUpTime)
        }else{
            [System.Windows.Forms.MessageBox]::Show('No computer selected.')
        }
        
    }catch{
        [System.Windows.Forms.MessageBox]::Show($_)
    }
    

}

#Shadow selected session based on session information collected in Search-Computer function
function Start-Shadow{
    if($lbSessions.SelectedItem){
        $selectedSession = $lbSessions.SelectedItem
        $sessionID = (-split $selectedSession)[1]
        mstsc.exe /v:$($tbComputerName.Text) /shadow:$sessionID /f /span /control
    }else{
        [System.Windows.Forms.MessageBox]::Show("No session selected.")
    }
}

function Send-Email{
    $WebRequest = Invoke-WebRequest "https://raw.githubusercontent.com/bwidom/helpdesk-tool/refs/heads/main/EmailWindow.xaml"
    [xml]$XAML = $WebRequest.Content
    #[xml]$XAML = Get-Content 'EmailWindow.xaml'

    $XAML.Window.RemoveAttribute('x:Class')
    $XAML.Window.RemoveAttribute('mc:Ignorable')
    $XAMLReader = New-Object System.Xml.XmlNodeReader $XAML
    $EmailWindow = [Windows.Markup.XamlReader]::Load($XAMLReader)
    $XAML.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $EmailWindow.FindName($_.Name)}

    $user = Get-AdUser -Identity $lSAMAccountName.Text -Properties EmailAddress
    $outlook = New-Object -ComObject Outlook.Application
    $mail = $outlook.createItem(0)
    $mail.To = $user.EmailAddress
    $mail.Subject = 'ITT Service Request SR# '
    $mail.Display()

    $cbTemplate = $EmailWindow.FindName("cbTemplate")
    $bSelectTemplate = $EmailWindow.FindName('bSelectTemplate')

    $csv = Import-Csv "C:\Users\bbame\Documents\Templates.txt"
    $csv | ForEach-Object{$cbTemplate.AddChild($_.Name)}

    $bSelectTemplate.Add_Click({Select-Template})

    function Select-Template{
        $templateName = $cbTemplate.SelectedItem
        $template = $csv | Where-Object{$_.Name -eq $templateName} | Select-Object -ExpandProperty Template
        $bodyBuffer = ''
        $template | ForEach-Object {$bodyBuffer += $_}
        $Mail.HTMLBody = "$(Get-EmailHeader) <br><br> $bodyBuffer $($Mail.HTMLBody)"
    }

    Function Get-EmailHeader{
        $timeOfDay = if((Get-Date).Hour -lt 12){'morning'}else{'afternoon'}
        return "Good $timeOfDay, $($user.GivenName),`n`n"
    }
    
    $EmailWindow.ShowDialog()|out-null
}

function Create-UserInfoWindow{
    if($lSAMAccountName.Text){
        $WebRequest = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bwidom/helpdesk-tool/refs/heads/main/UserInfoWindow.xaml"
        [xml]$XAML = $WebRequest.Content
        #[xml]$XAML = Get-Content 'UserInfoWindow.xaml'

        $XAML.Window.RemoveAttribute('x:Class')
        $XAML.Window.RemoveAttribute('mc:Ignorable')
        $XAMLReader = New-Object System.Xml.XmlNodeReader $XAML
        $UserInfoWindow = [Windows.Markup.XamlReader]::Load($XAMLReader)
        $XAML.SelectNodes("//*[@Name]") | Where-Object {Set-Variable -Name ($_.Name) -Value $UserInfoWindow.FindName($_.Name)}
        $UserInfoWindow.Title = $lSAMAccountName.Text
        $UserInfoWindow.Owner = $MainWindow
        $UserInfoWindow.WindowStartupLocation = 'CenterOwner'

        $tbEmailAddress = $UserInfoWindow.FindName('tbEmailAddress')
        $tbDescription = $UserInfoWindow.FindName('tbDescription')
        $tbAddress = $UserInfoWindow.FindName('tbAddress')
        $tbTelephone = $UserInfoWindow.FindName('tbTelephone')
        $tbMobilePhone = $UserInfoWindow.FindName('tbMobilePhone')
        $tbOtherLoginWorkstation = $UserInfoWindow.FindName('tbOtherLoginWorkstation')
        $tbCanonicalName = $UserInfoWindow.FindName('tbCanonicalName')
        $tbProfilePath = $UserInfoWindow.FindName('tbProfilePath')
        $tbExpiresOn = $UserInfoWindow.FindName('tbExpiresOn')
        $lbMemberOf = $UserInfoWindow.FindName('lbMemberOf')
        
        $Properties = @('EmailAddress','Description','Office','telephoneNumber','MobilePhone','otherLoginWorkstations','CanonicalName','HomeDirectory','AccountExpirationDate','MemberOf')

        $User = Get-ADUser -Filter {SAMAccountName -eq $lSAMAccountName.Text} -Properties $Properties
        $tbAddress.Text = $User.Office
        $tbDescription.Text = $User.Description
        $tbEmailAddress.Text = $User.EmailAddress
        $tbTelephone.Text = $User.telephoneNumber
        $tbMobilePhone.Text = $User.MobilePhone
        $tbOtherLoginWorkstation.Text = $User.otherLoginWorkstations
        $tbCanonicalName.Text = $User.CanonicalName
        $tbProfilePath.Text = $User.HomeDirectory
        $tbExpiresOn.Text = $User.AccountExpirationDate
        #Get-ADPrincipalGroupMembership -Identity $lSAMAccountName.Text | ForEach-Object {$lbMemberOf.AddChild($_.name)}
        (Get-ADUser -Filter {SAMAccountName -eq $lSAMAccountName.Text} -Properties MemberOf).MemberOf | ForEach-Object {$lbMemberOf.AddChild(($_ -split ',')[0].Substring(3))}

        $UserInfoWindow.ShowDialog() | Out-Null
    }else{
        Write-Host "No user Selected"
    }
}

$bSearch = $MainWindow.FindName("bSearch")
$bSearch.Add_Click({Search-User})

$bUnlock = $MainWindow.FindName("bUnlock")
$bUnlock.Add_Click({Unlock-User})

$bChangePassword = $MainWindow.FindName("bChangePassword")
$bChangePassword.Add_Click({Create-PasswordWindow})

$bSearchComputer = $MainWindow.FindName("bSearchComputer")
$bSearchComputer.Add_Click({Search-Computer})

$bShadow = $MainWindow.FindName("bShadow")
$bShadow.Add_Click({Start-Shadow})

$bSendEmail = $MainWindow.FindName('bSendEmail')
$bSendEmail.Add_Click({Send-Email})

$bMoreUserInfo = $MainWindow.FindName('bMoreUserInfo')
$bMoreUserInfo.Add_Click({Create-UserinfoWindow})

$MainWindow.ShowDialog() | Out-Null

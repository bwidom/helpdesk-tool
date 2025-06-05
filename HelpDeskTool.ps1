Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
$WebRequest = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bwidom/helpdesk-tool/refs/heads/main/MainWindow.xaml"
[xml]$XAML = $WebRequest.Content
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

try{
    Get-ADComputer | Select-Object -First 1
    $ADEnvironment = "True"
}catch{
    Write-Host "Active Directory not installed, using test data"
    $ADEnvironment = "False"
}


function Search-User{
    
    switch($cbSearchCriteria.SelectedIndex){
        0{
            $criteria = "EmployeeID"
        }
        1{
            $criteria = "SAMAccountName"            
        }
    }

    if($ADEnvironment -eq "True"){
        Write-Host "AD installed"
        $User = Get-ADUser -Filter {$criteria -eq $tbSearchUser.Text} -Properties * | Select-Object LastBadPasswordAttempt, PasswordLastSet, PasswordExpired, BadLogonCount, LockedOut, EmployeeID, SAMAccountName
    }else{
        $User = [PSCustomObject]@{
            LastBadPasswordAttempt = Get-Date
            PasswordLastSet = Get-Date
            PasswordExpired = "Not Expired"
            LockedOut = "Not Locked"
            BadLogonCount = 1
            EmployeeID = 123456
            SAMAccountName = "john.doe"
        }
    }
    if($User){
        $dgAccountInfo.ItemsSource= @([PSCustomObject]@{
            LastBadPassword = $User.LastBadPasswordAttempt
            PasswordLastSet = if($User.PasswordLastSet){$User.PasswordLastSet}else{"Change Password"}
            PasswordExpired = if($User.PasswordLastSet){if($User.PasswordExpired){"Expired"}else{"Not Expired"}}else{""}
            LockedOut = if($User.LockedOut){"Locked"}else{"Unlocked"}
            BadLogonCount = $User.BadLogonCount
        })
        $lEmployeeID.Content = $User.EmployeeID
        $lSAMAccountName.Content = $User.SAMAccountName
        
    }else{
        Write-Host "User Not Found"
    }
    
}

function Unlock-User{
    if($lSAMAccountName.Content){
        $DCs = Get-ADDomainController
        foreach($DC in $DCs){
            Unlock-ADAccount -Identity $lSAMAccountName.Content -Server $DC
        }
        Search-User
    }else{
        Write-Host "No User Selected"
    }

}

function Spawn-PasswordWindow{
    if($lSAMAccountName.Content){
        $WebRequest = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bwidom/helpdesk-tool/refs/heads/main/ChangePasswordWindow.xaml"
        [xml]$XAML = $WebRequest.Content
        $XAML.Window.RemoveAttribute('x:Class')
        $XAML.Window.RemoveAttribute('mc:Ignorable')
        $XAMLReader = New-Object System.Xml.XmlNodeReader $XAML
        $ChangePasswordWindow = [Windows.Markup.XamlReader]::Load($XAMLReader)
        $XAML.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $ChangePasswordWindow.FindName($_.Name)}

        $lChangePasswordPrompt = $ChangePasswordWindow.FindName("lChangePasswordPrompt")
        $lChangePasswordPrompt.Content = "Change " + $lSAMAccountName.Content + "'s password to:"

        $digits = $lEmployeeID.Content.Substring($lEmployeeID.Content.Length - 2)
        $password = "Changepasswordnow" + $Digits
        $tbNewPassword = $ChangePasswordWindow.FindName("tbNewPassword")
        $tbNewPassword.Text = $password

        function Change-UserPassword{
            Set-ADAccountPassword -Identity $lSAMAccountName.Content -NewPassword (ConvertTo-SecureString -AsPlainText $tbNewPassword.Text -Force) -Reset
            Set-ADUser -Identity $lSAMAccountName.Content -ChangePasswordAtLogon $true
            [System.Windows.Forms.MessageBox]::Show("Password Changed")
            $ChangePasswordWindow.Close()
        }

        $bConfirm = $ChangePasswordWindow.FindName("bConfirm")
        $bConfirm.Add_Click({Change-UserPassword})

        $bCancel = $ChangePasswordWindow.FindName("bCancel")
        $bCancel.Add_Click({$ChangePasswordWindow.Close()})

        $ChangePasswordWindow.ShowDialog() | Out-Null
    }
}

$bSearch = $MainWindow.FindName("bSearch")
$bSearch.Add_Click({Search-User})

$bUnlock = $MainWindow.FindName("bUnlock")
$bUnlock.Add_Click({Unlock-User})

$bChangePassword = $MainWindow.FindName("bChangePassword")
$bChangePassword.Add_Click({Spawn-PasswordWindow})

$MainWindow.ShowDialog() | Out-Null


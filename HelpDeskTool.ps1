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

$dataTable = New-Object System.Data.DataTable

[void]$dataTable.Columns.Add("DC Name", [string])
[void]$dataTable.Columns.Add("LastBadPassword", [string])
[void]$dataTable.Columns.Add("PasswordLastSet", [string])
[void]$dataTable.Columns.Add("PasswordExpired", [string])
[void]$dataTable.Columns.Add("LockedOut", [string])
[void]$dataTable.Columns.Add("BadLogonCount", [int])

$dgAccountInfo.ItemsSource = $dataTable.DefaultView


$dcs = @(Get-ADDomainController -Filter * | Sort-Object -Property Name)
$rows = [Object[]]::new($dcs.Count)
for($i=0; $i -lt $dcs.Count; $i++){
    $rows[$i] = $dataTable.NewRow()
    $dataTable.Rows.Add($rows[$i])
}


function Search-User{
    $lEmployeeID.Content = "Collecting data..."
    $lSAMAccountName.Content = ""
    [System.Windows.Forms.Application]::DoEvents()
    switch($cbSearchCriteria.SelectedIndex){
        0{
            $criteria = "EmployeeID"
        }
        1{
            $criteria = "SAMAccountName"            
        }
    }

    $properties = @("LastBadPasswordAttempt", "PasswordLastSet", "PasswordExpired", "BadLogonCount", "LockedOut", "EmployeeID", "SAMAccountName")

    $countUser = @(Get-ADUser -Filter {($criteria -eq $tbSearchUser.Text) -AND (Enabled -eq $true)})
    if($countUser.Count -eq 1){
        for($i = 0; $i -lt $dcs.Count; $i++){ 
            if(Test-Connection ($dcs[$i]).Name -Count 1 -Quiet){
                $userInfoOnServer = @(Get-ADUser -Server $dcs[$i] -Filter {($criteria -eq $tbSearchUser.Text) -AND (Enabled -eq $true)} -Properties $properties| Select-Object $properties)
                $rows[$i]["LastBadPassword"] = $userInfoOnServer.LastBadPasswordAttempt
                $rows[$i]["PasswordLastSet"] = if($userInfoOnServer.PasswordLastSet){$userInfoOnServer.PasswordLastSet}else{"Change Password"}
                $rows[$i]["PasswordExpired"] = if($userInfoOnServer.PasswordLastSet){if($userInfoOnServer.PasswordExpired){"Expired"}else{"Not Expired"}}else{"N/A"}
                $rows[$i]["LockedOut"] = if((Get-ADUser -Filter {($criteria -eq $tbSearchUser.Text) -AND (Enabled -eq $true)} -Properties * | Select-Object -ExpandProperty lockoutTime) -gt 0){"Locked"}else{"Unlocked"}
                $rows[$i]["BadLogonCount"] = if($userInfoOnServer.BadLogonCount){$userInfoOnServer.BadLogonCount}else{[DBNull]::Value}
                $rows[$i]["DC Name"] = $dcs[$i].Name
            }else{
                $rows[$i]["DC Name"] = $dcs[$i].Name
                $rows[$i]["LockedOut"] = "DC Unavailable"
            }
        }
        $lEmployeeID.Content = $userInfoOnServer.EmployeeID
        $lSAMAccountName.Content = $userInfoOnServer.SAMAccountName
    }elseif($countUser.Count -eq 0){
        for($i = 0; $i -lt $dcs.Count; $i++){             
            $rows[$i]["LastBadPassword"] = [string]::Empty
            $rows[$i]["PasswordLastSet"] = [string]::Empty
            $rows[$i]["PasswordExpired"] = [string]::Empty
            $rows[$i]["LockedOut"] = [string]::Empty
            $rows[$i]["BadLogonCount"] = [DBNull]::Value
            $rows[$i]["DC Name"] = [string]::Empty
        }
        $lEmployeeID.Content = "User Not Found"
        $lSAMAccountName.Content = ""
    }elseif($countUser.Count -gt 1){
        for($i = 0; $i -lt $dcs.Count; $i++){             
            $rows[$i]["LastBadPassword"] = [string]::Empty
            $rows[$i]["PasswordLastSet"] = [string]::Empty
            $rows[$i]["PasswordExpired"] = [string]::Empty
            $rows[$i]["LockedOut"] = [string]::Empty
            $rows[$i]["BadLogonCount"] = [DBNull]::Value
            $rows[$i]["DC Name"] = [string]::Empty
        }
        $lEmployeeID.Content = "Multiple Users Found"
        $lSAMAccountName.Content = ""
    }
}

function Unlock-User{
    if($lSAMAccountName.Content){
        foreach($dc in $dcs){
            if(Test-Connection ($dc).Name -Count 1 -Quiet){
                Unlock-ADAccount -Identity $lSAMAccountName.Content -Server $dc
            }
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
            #Set-ADUser -Identity $lSAMAccountName.Content -ChangePasswordAtLogon $true
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

function Clear-Window{
    for($i = 0; $i -lt $dcs.Count; $i++){             
        $rows[$i]["LastBadPassword"] = [string]::Empty
        $rows[$i]["PasswordLastSet"] = [string]::Empty
        $rows[$i]["PasswordExpired"] = [string]::Empty
        $rows[$i]["LockedOut"] = [string]::Empty
        $rows[$i]["BadLogonCount"] = [DBNull]::Value
        $rows[$i]["DC Name"] = [string]::Empty
    }
    $lEmployeeID.Content = "User Not Found"
    $lSAMAccountName.Content = ""
}

$bSearch = $MainWindow.FindName("bSearch")
$bSearch.Add_Click({Search-User})

$bUnlock = $MainWindow.FindName("bUnlock")
$bUnlock.Add_Click({Unlock-User})

$bChangePassword = $MainWindow.FindName("bChangePassword")
$bChangePassword.Add_Click({Spawn-PasswordWindow})


$MainWindow.ShowDialog() | Out-Null

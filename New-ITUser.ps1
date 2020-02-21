#Requires -Modules ActiveDirectory
#Requires -Modules PSWriteWord

<#  
    .DESCRIPTION 
    A script to create user account in AD, Exchange 2013 and Lync 2013

    .NOTES
    Written by: Tomas Cerniauskas
   
#>

# Start Stopwatch to track the duration of whole script and output it to the screen at the end
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
function New-SWRandomPassword {
    <#
        .NOTES
            Function written by Simon Wåhlin
            http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}

function New-Username {
    <#
        .FUNCTIONALITY
            Generates username in such sequence and after each step checks with AD:
                Example1: John Smith
                    Step1: Smith
                    Step2: SmithJ
                    Step3: SmithJo
                    Step4: (continue until username is not taken in AD)
                
                Example2: Jane Dos-Tres
                    Step1: Dos
                    Step2: DosT
                    ...
                    Step(n): DosTres
                    Step(n+1): DosTresJ
                    Step(n+2): DosTresJa
                    Step(n+k): (continue until username is not taken in AD)
    #>
    [cmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$Firstname,
        [Parameter(Mandatory=$True)]
        [string]$Lastname,
        [Parameter(Mandatory=$True)]
        [string]$FullName
    )
    $Proceed = $False

    $LegacyUsers = import-csv -path "$PSScriptroot\HistoricalUsers.csv" -Encoding UTF7
    
    $HashTable = @{}
    foreach ($name in $LegacyUsers) {
        $HashTable[$name.IDNAME]=$name.FULLNAME
    }

    $Firstname = $Firstname.ToLower()
    $Lastname = $Lastname.ToLower()
    
    # Names have to be normalized, otherwise the username might have non-latin characters
    $FirstName = $FirstName.Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('ß','ss')
    $FirstName = [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($FirstName))

    $LastName = $LastName.Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('ß','ss')
    $LastName = [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($LastName))

    # Check if provided Lastname contains spaces, dashes or apostrophes, for example like "O'Neal", "van der Beek" or "Schmidt-Martinez"
    if ($Lastname -match " |-|'") { 
        
        # Split the last name into separate words using delimiters " ", "-" and "'" 
        $LastnameSplit = $Lastname.Split(" -'")
        $SubstringCountUsed = 0

        
        if ($LastnameSplit[0] -match "Al|Da|De|Del|Der|Di|El|La|Mc|O|Van|Von") {

            if ($LastnameSplit[1] -match "Del|Den|Der|La|Van|Von") {
                $SubstringCountUsed = 3
                $username = $LastnameSplit[0]+$LastnameSplit[1]+$LastnameSplit[2]
                
            } else {
                $SubstringCountUsed = 2
                $username = $LastnameSplit[0]+$LastnameSplit[1]
                
            }

        } else {
            $SubstringCountUsed = 1
            $username = $LastnameSplit[0]
        }

        $i = 0    
        $Proceed = $false    
        Do {
            try {
                $User = Get-ADUser -Identity $Username
            }
            catch { }
            
            if ($User) {
                Clear-Variable User
                if ($LastnameSplit[$SubstringCountUsed]) {
                    Do {
                        $Username += $LastnameSplit[$SubstringCountUsed].Substring($i,1)
                        try {
                            $User = Get-ADUser -Identity $Username
                        }
                        catch { }
            
                        if ($User) {
                             Clear-Variable User
                        } else { 
                            if (($HashTable[$username]) -and ($HashTable[$username] -ne $FullName)) {
                                $Proceed = $False
                            } else {
                                $Proceed = $True
                            }
                        }
                        $i++
                        
                    } Until ($Proceed)
                    
                    Clear-Variable User
                } else {  
                    
                    Do {
                        $Username += $Firstname.Substring($i,1)
                        try {
                            $User = Get-ADUser -Identity $Username
                        }
                        catch { }
            
                        if ($User) {
                             Clear-Variable User
                        } else { 
                            if (($HashTable[$username]) -and ($HashTable[$username] -ne $FullName)) {
                                $Proceed = $False
                            } else {
                                $Proceed = $True
                            }
                            
                        }
                        $i++
                        
                    } Until ($Proceed)
                }
            } else {
                
                if (($HashTable[$username]) -and ($HashTable[$username] -ne $FullName)) {
                    $Proceed = $False
                } else {
                    $Proceed = $True
                }
                
            }
            $i++
        } Until ($Proceed)

    } else {
        $Username = $Lastname
        $i = 0
        Do {
            try {
                $User = Get-ADUser -Identity $Username
            }
            catch { }

            if ($User) {
                $Username += $Firstname.Substring($i,1) 
                Clear-Variable User
            } else { 

                if (($HashTable[$username]) -and ($HashTable[$username] -ne $FullName)) {
                    $Username += $Firstname.Substring($i,1) 
                    
                } else {
                    $Proceed = $True
                }
            }
            $i++
            
        } Until ($Proceed)
        
    }
    
    $Proceed = $False
    
    # Username has to be less or equal to 12 characters, for SAP purposes
    if ($username.length -gt 12) {
        $username = $Username.Substring(0,12)
        [int]$UsernameLength = 12
    } else {
        [int]$UsernameLength = $Username.length
    }

    Do {
        try {
            $User = Get-ADUser -Identity $Username
        }
        catch { }
        if ($User) {
            $UsernameLength -= 1 
            $username = $Username.Substring(0,$UsernameLength)
            Clear-Variable User
        } else { 

            if (($HashTable[$username]) -and ($HashTable[$username] -ne $FullName)) {
                
                $UsernameLength -= 1 
                $username = $Username.Substring(0,$UsernameLength)
                
            } else {
                $Proceed = $True
            }

        }
        
     } Until ($Proceed)
    
    Write-Output (Get-Culture).TextInfo.ToTitleCase($Username)

}

function New-ExchangeMailbox {
    [CmdletBinding()]
	param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [ValidateSet('Staff','Contractor','Local employee','Temporary employee')]
        [string]$EmployeeType,
        [string]$Logfile
	)
	process {
        # Defined variables for mailbox configurations
        $ExchangeServer = 'exchangeserver01'
        $ActiveSyncMailboxPolicy = '01234567-5555-4040-aacc-0123456789cc'
        $OwaMailboxPolicy = '01234567-1212-1111-cccc-0123456789cc'
        $RetentionPolicy = 'Pre-Pilot-Archive-Policy-Exchange2013-V1.0'

        Write-Color " Connecting to Exchange server $ExchangeServer using PSRemoting... " -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeServer/PowerShell/ -Authentication Kerberos -AllowRedirection
        
        # Connect to Exchange server using PSRemoting
        Import-PSSession $Session -DisableNameChecking -CommandName Enable-Mailbox,Get-Mailbox,Set-Mailbox,Set-CASMailbox > $null
        Write-Color 'Done' -Color Green -LogFile $LogFile

        [string]$ID = Get-ADUser $Username -Property ObjectGuid | Select-Object -Expandproperty objectGUID

        Write-Color ' Creating mailbox for ',"$username",'... ' -Color Yellow,Cyan,Yellow -NoNewLine -ShowTime -LogFile $LogFile
        
        $Proceed = $true
        Do {
            Enable-Mailbox -Identity $ID > $null
            if (!($?)) {
                $Proceed = $false
                Write-Color ' Failed. ','Retrying in 3 seconds... ' -Color Red,Yellow -ShowTime -LogFile $LogFile
                Start-Sleep -Seconds 3
            } else {
                $Proceed = $true
            }
        } Until ($Proceed)
                
        Write-Color 'Done' -Color Green -LogFile $LogFile

        $Archive = (Get-Mailbox -Identity $ID -ReadFromDomainController:$true).Database.Replace('MBX','ARC') 

        Write-Color " Enabling Archive mailbox on $Archive... " -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        Enable-Mailbox -Identity $ID -Archive:$true -ArchiveDatabase $Archive > $null
        Write-Color 'Done' -Color Green -LogFile $LogFile

        if ($EmployeeType -eq 'Contractor') {
            $OldPrimaryAddress=(Get-Mailbox -Identity $ID -ReadFromDomainController:$true).PrimarySmtpAddress
            $ExternalMail = (Get-Mailbox -Identity $ID -ReadFromDomainController:$true).PrimarySmtpAddress.Replace('@','@external.')

            Write-Color ' Creating email address ',"$ExternalMail",' and setting it as Primary address... ' -Color Yellow,Cyan,Yellow -NoNewLine -ShowTime -LogFile $LogFile
            Set-Mailbox -Identity $ID -EmailAddresses @{add="$ExternalMail"}
            Set-Mailbox -Identity $ID -PrimarySmtpAddress $ExternalMail -EmailAddressPolicyEnabled:$false
            Write-Color 'Done' -Color Green -LogFile $LogFile
            Write-Color ' Deleting email address ',"$OldPrimaryAddress",'... ' -Color Yellow,Cyan,Yellow -NoNewLine -ShowTime -LogFile $LogFile
            Set-Mailbox -Identity $ID -EmailAddresses @{remove="$OldPrimaryAddress"}
            Write-Color 'Done' -Color Green -LogFile $LogFile
        } 

        Write-Color ' Configuring Mobile Device ActiveSync policy... ' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        Set-CASMailbox -Identity $ID -ActiveSyncMailboxPolicy $ActiveSyncMailboxPolicy 
        Write-Color 'Done' -Color Green -LogFile $LogFile
       
        Write-Color ' Disabling IMAP and POP3... ' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        Set-CASMailbox -Identity $ID -PopEnabled:$false -ImapEnabled:$false 
        Write-Color 'Done' -Color Green -LogFile $LogFile

        Write-Color ' Configuring Outlook Web Access... ' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        Set-CASMailbox -Identity $ID -OwaMailboxPolicy $OwaMailboxPolicy
        Write-Color 'Done' -Color Green -LogFile $LogFile

        Write-Color ' Configuring default Retention Policy... ' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        Set-Mailbox -Identity $ID -RetentionPolicy $RetentionPolicy
        Write-Color 'Done' -Color Green -LogFile $LogFile

        Remove-PSSession $Session
    }
}

function New-WelcomeMemo {
    [CmdletBinding()]
	param (
        [string]$Firstname,
        [string]$Lastname,
        [string]$Username,
        [string]$Email,
        [string]$Acronym,
        [string]$Password,
        [string]$LogFile
	)
	process {
        $FilePathTemplate = "$PSScriptRoot\Welcome Memo Template.docx"
        $FilePathMemo = "$PSScriptRoot\Welcome Memo for $Firstname $Lastname.docx"

        $WordDocument = Get-WordDocument -FilePath $FilePathTemplate

        Add-WordCustomProperty -WordDocument $WordDocument -Name 'Username'  -Value $Username -Supress $True
        Add-WordCustomProperty -WordDocument $WordDocument -Name 'Email'  -Value $Email -Supress $True
        Add-WordCustomProperty -WordDocument $WordDocument -Name 'Acronym'  -Value $Acronym -Supress $True
        Add-WordCustomProperty -WordDocument $WordDocument -Name 'Password'  -Value $Password -Supress $True
        Save-WordDocument -WordDocument $WordDocument -FilePath $FilePathMemo -Supress $True
        Write-Color ' Created ',"$FilePathMemo" -Color Yellow,Green -ShowTime -LogFile $LogFile
    }
}

Write-Color ' Opening XML file and parsing contents... ' -Color Yellow -NoNewLine -ShowTime
$AccountRequestXMLfile = 'Account_Request.xml'
[xml]$AccountRequest = Get-Content $PSScriptRoot\$AccountRequestXMLfile -ErrorAction Stop

$Description = $AccountRequest.rss.channel.item.description
$Company = 'Adatum'
$Personnelnumber = ''
$Acronym = ''

if ($Description -match "Division: (\w{2,4})") {
    $Division = $matches[1]
}

if ($Description -match "Last Name: (.+)<") {
    $LastName = (Get-Culture).TextInfo.ToTitleCase($matches[1].ToLower())   
}

if ($Description -match "First Name: (.+)<") {
    $FirstName = (Get-Culture).TextInfo.ToTitleCase($matches[1].ToLower())
}

$DisplayName = "$FirstName $LastName"

# Exchange doesn't normalize Roman letters ș and ț
$FirstName = $FirstName.Replace('Ș','S').Replace('Ț','t').Replace('ș','s').Replace('ț','t')
$LastName = $LastName.Replace('Ș','S').Replace('Ț','t').Replace('ș','s').Replace('ț','t')

if ($Description -match "Employee group: (\w)") {
    switch ($matches[1]) {
      "S" { $EmployeeType = 'Staff'; break }
      "C" { $EmployeeType = 'Contractor'; break }
      "L" { $EmployeeType = 'Local Employees'; break }
      "T" { $EmployeeType = 'Temporary Employees'; break }
      "I" { $EmployeeType = 'Contractor'; break }  # Intern
      "O" { $EmployeeType = 'Contractor'; break }  # Other (Visitor, Trainee)
     }    
}

if ($Description -match "Contract End Date: (.+)<") {
    $ContractEndDate = [DateTime]::ParseExact($matches[1],"dd MMM yyyy",$null)
}

if ($Description -match "Job Title: (.*)<") {
    $Title = $matches[1]
}

if ($Description -match "Technical Officer: (.+)<") {
    $TechnicalOfficer = $matches[1]
}

if ($Description -match "Company: (.+)<") {
    $Company = $matches[1]
}

if ($Description -match "on the intranet: (\w)") {
    $HideFromOrgchart = switch ($matches[1]) {
                            'y' { 'no' }
                            'n' { 'yes' }
                        }
}

if ($Description -match "Personnel number: (\d+)<") {
    $Personnelnumber = $matches[1]
}

if ($Description -match "Acronym: (.+)<") {
    $Acronym = $matches[1]
}

if ($Description -match "placed: (.+)<") {
    $Office = $matches[1]
}

$Comment = $AccountRequest.rss.channel.item.key.'#text'

Write-Color 'Done' -Color Green

Write-Color ' Generating new username... ' -Color Yellow -NoNewLine -ShowTime
$Username = New-Username -Firstname $FirstName -Lastname $LastName -FullName $DisplayName
Write-Color 'Done' -Color Green 

$Location = 'OU=Users'
$DomainDn = (Get-AdDomain).DistinguishedName
$UPNSuffix = '@adatum.com'

# Creating a log file
$Date = Get-Date -Format FileDate
$Filename = $date+'_'+"$Username"+'.log'
$LogFile = Join-Path $PSScriptRoot ($Filename)

if (!(Test-Path -Path $LogFile)) {
    New-Item -Path $PSScriptRoot -Name $Filename > $null
}

# Generate random 12 character password
Write-Color ' Generating random password... ' -Color Yellow -NoNewLine -ShowTime
$DefaultPassword = New-SWRandomPassword -PasswordLength 12
Write-Color 'Done' -Color Green

Write-Color ' ---Parsing XML has generated these variables---' -Color Yellow -LinesBefore 1 -ShowTime -LogFile $LogFile
Write-Color ' First Name: ',"$FirstName" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Last Name: ',"$LastName" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Display Name: ',"$DisplayName" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Username: ',"$Username" -Color Yellow,Cyan -ShowTime -LogFile $LogFile
Write-Color ' Contract End Date: ',"$ContractEndDate" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Employee Type: ',"$EmployeeType" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Acronym: ',"$Acronym" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Division: ',"$Division" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Company: ',"$Company" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Hide from Orgchart? ',"$HideFromOrgchart" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Personel Number: ',"$PersonnelNumber" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Title: ',"$Title" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Technical Officer: ',"$TechnicalOfficer" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Office: ',"$Office" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' Description: ',"$Comment" -Color Yellow,Green -ShowTime -LogFile $LogFile
Write-Color ' -----------------------------' -Color Yellow -ShowTime -LogFile $LogFile

# Checking if the user is Staff or Contractor/Local Staff/Temporary Staff
if ([Regex]::Matches($Acronym, "\/").Count -eq 2) {
    $UserTemplate = Get-ADUser AdTmpNS -Properties MemberOf
} else {
    $UserTemplate = Get-ADUser AdTmpSt -Properties MemberOf
}

$NewUserParams = @{
    'Instance' = $UserTemplate
    'UserPrincipalName' = $Username + $UPNSuffix
    'Name' = $DisplayName
    'GivenName' = $FirstName
    'DisplayName' = $DisplayName
    'Surname' = $LastName
    'SamAccountName' = $Username
    'AccountPassword' = (ConvertTo-SecureString $DefaultPassword -AsPlainText -Force)
    'Enabled' = $true
    'Path' = "$Location,$DomainDn"
    'ChangePasswordAtLogon' = $true
    'AccountExpirationDate' = $ContractEndDate
    'Office' = $Office
    'Company' = $Company
    'Division' = $Division
    'Description' = $Comment
    'OtherAttributes' = @{extensionAttribute3="$HideFromOrgchart";extensionAttribute6="$Acronym";employeeType="$EmployeeType"}
}

Write-Color ' Creating new user account: ',"$username " -Color Yellow,Cyan -NoNewLine -ShowTime -LogFile $LogFile
New-AdUser @NewUserParams -ErrorAction Stop
Write-Color 'Done' -Color Green -LogFile $LogFile

[int]$Sleep = 10
Write-Color " Sleeping for $Sleep seconds before the Exchange configuration" -Color Yellow -ShowTime -LogFile $LogFile
Start-Sleep -Seconds $Sleep

# Homedrive creation
$Grant ="/grant"
$HomeDriveServer1 = '\\fileserver01\user1'
$HomeDriveServer2 = '\\fileserver02\user2'
$HomeDriveServer3 = '\\fileserver03\user3'
$HomeDriveServer4 = '\\fileserver04\user4'
$NetBIOSDomainName = 'ADATUM'

# Create Home drive H:
Write-Color ' Creating H: drive and assigning FULL permissions... ' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
switch -regex ($Username.SubString(0,1)) {
    "^[a-e]" { 
                $HomeDir = "$HomeDriveServer1\$Username" 
                New-Item -Path $HomeDir -ItemType Directory > $null
                $UserPermission = "$NetBIOSDomainName\$username`:(OI)(CI)(F)"
                icacls $HomeDir $Grant $UserPermission
            }
    "^[f-j]" { 
                $HomeDir = "$HomeDriveServer2\$Username" 
                New-Item -Path $HomeDir -ItemType Directory > $null
                $UserPermission = "$NetBIOSDomainName\$username`:(OI)(CI)(F)"
                icacls $HomeDir $Grant $UserPermission
    }
    "^[k-p]" { 
                $HomeDir = "$HomeDriveServer3\$Username" 
                New-Item -Path $HomeDir -ItemType Directory > $null
                $UserPermission = "$NetBIOSDomainName\$username`:(OI)(CI)(F)"
                icacls $HomeDir $Grant $UserPermission
    }
    "^[r-z]" { 
                $HomeDir = "$HomeDriveServer4\$Username" 
                New-Item -Path $HomeDir -ItemType Directory > $null
                $UserPermission = "$NetBIOSDomainName\$username`:(OI)(CI)(F)"
                icacls $HomeDir $Grant $UserPermission
    }
    Default {}
}
Write-Color "Homedrive H: created" -Color Green -LogFile $LogFile


Write-Color " Assigning default user groups for $EmployeeType based on the Template... " -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
foreach ($group in $UserTemplate.MemberOf) {
    Add-ADGroupMember -Identity $group -Members $Username
}
Write-Color 'Done' -Color Green -LogFile $LogFile

if ($EmployeeType -eq 'Contractor') {
    if ($TechnicalOfficer) {
        Set-ADUser -Identity $Username -Add @{extensionAttribute8="$TechnicalOfficer"}
    } 
    Set-ADUser -Identity $Username -Add @{HomeDirectory="$HomeDir";HomeDrive="H:"}
} else {
    $TechnicalOfficer = (Get-ADUser -Filter {DisplayName -eq $TechnicalOfficer}).DistinguishedName
    Set-ADUser -Identity $Username -Add @{manager="$TechnicalOfficer"} 
    Set-ADUser -Identity $Username -Add @{EmployeeNumber="$PersonnelNumber";title="$Title";HomeDirectory="$HomeDir";HomeDrive="H:"}
}

switch ($EmployeeType) {
    "Local employees" {
        Write-Color ' Removing user from Contractor groups and adding Local Staff groups... ' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        Remove-ADGroupMember -Identity 'Contractors' -Members $Username -Confirm:$false
        Remove-ADGroupMember -Identity 'Grp Contractors' -Members $Username -Confirm:$false
        Add-ADGroupMember -Identity 'LocalStaff' -Members $Username
        Add-ADGroupMember -Identity 'Grp LocalStaff' -Members $Username
        Write-Color 'Done' -Color Green -LogFile $LogFile
    }
    "Temporary employees" { 
        Write-Color ' Removing user from Contractor groups and adding Temporary Staff groups' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
        Remove-ADGroupMember -Identity 'Contractors' -Members $Username -Confirm:$false
        Remove-ADGroupMember -Identity 'Grp Contractors' -Members $Username -Confirm:$false
        Add-ADGroupMember -Identity 'TemporaryStaff' -Members $Username
        Add-ADGroupMember -Identity 'GRP STAFF TEMP' -Members $Username
        Write-Color 'Done' -Color Green -LogFile $LogFile
    }
    Default {}
}

New-ExchangeMailbox -Username $Username -EmployeeType $EmployeeType -Logfile $LogFile

Write-Color " Sleeping for $Sleep seconds before the Lync configuration" -Color Yellow -ShowTime -LogFile $LogFile
Start-Sleep -Seconds $Sleep

$Proceed = $true

# Creating Skype for Business (Lync 2013) account
Write-Color ' Creating Lync account... '  -Color Yellow -ShowTime -LogFile $LogFile
$LyncServer = 'lyncserver01'
$RegistrarPool = 'lyncserver01'

Do {
    Invoke-Command -ConnectionUri  https://$LyncServer/OcsPowershell -Authentication Negotiate { Enable-CsUser $using:Username -RegistrarPool $using:RegistrarPool -SipAddressType EmailAddress }
    if (!($?)) {
        $Proceed = $false
        Write-Color ' Failed. ','Retrying in 3 seconds... ' -Color Red,Yellow -ShowTime -LogFile $LogFile
        Start-Sleep -Seconds 3
    } else {
        $Proceed = $true
    }
} Until ($Proceed)

Write-Color 'Done' -Color Green -LogFile $LogFile

# Create Archive drive:
Write-Color ' Creating Archive Drive and granting Modify permissions... ' -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
$ArchiveDrive = '\\fileserver01\Archive'
$Folder = "$ArchiveDrive\$username"
New-Item -Path $Folder -ItemType Directory > $null
$UserPermission = "$NetBIOSDomainName\$username`:(OI)(CI)(M)"
icacls $Folder $Grant $UserPermission
Write-Color 'Done' -Color Green -LogFile $LogFile

$Email = (Get-ADUser $Username -properties mail).mail
Write-Color ' Creating Welcome Memo... ' -Color Yellow -ShowTime -LogFile $LogFile
New-WelcomeMemo -Firstname $FirstName -Lastname $Lastname -Username $Username -Email $Email -Acronym $Acronym -Password $DefaultPassword -LogFile $LogFile

$CrashPlanFile = "$PSScriptRoot\Crashplan.txt"
Write-Color ' Adding user details to Crashplan file... '  -Color Yellow -NoNewLine -ShowTime -LogFile $LogFile
"{0},{1},{2},{3},`"defaultpassword`"" -f $FirstName,$Lastname,$Username,$Email | Add-Content -path $CrashPlanFile
Write-Color 'Done' -Color Green -LogFile $LogFile

Write-Color ' Create and print Label with details: ',"$Acronym $FirstName $Lastname" -Color Magenta, Green -ShowTime -LogFile $LogFile
Write-Color ' Upload and print Welcome Memo' -Color Magenta -ShowTime -LogFile $LogFile

Write-Color ' Create SAP account: ',"$Username" -Color Magenta ,Green -ShowTime -LogFile $LogFile
Write-Color ' Upload CrashPlan file' -Color Magenta -ShowTime -LogFile $LogFile

$Stopwatch.Stop()
Write-Color ' Duration of the whole Script: ',$Stopwatch.Elapsed.Seconds,' seconds' -Color Yellow,Red,Yellow -ShowTime -LogFile $LogFile
Write-Color ' ---End of script---' -Color Green -ShowTime -LogFile $LogFile
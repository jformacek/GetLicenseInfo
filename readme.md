# GetLicenseInfo
Simple module that retrieves information about liceses assigned to user account and can display it as formatted report.

Module retrieves list of licenses subscribed by a tenant, plus retrieves recent list of product and SKU display names from Microsoft. Module then uses downloaded display names to enrich the output.

Usage
```powershell
$user = Get-LicenseInfo -UserPrincipalName user@domain.com -TenantId $domain.com

#display assigned licenses
$user.AssignedLicenses

#display license report, sorted by display name
$user.AssignedLicenses.Report()

#display license report, sorted by assigned time
$user.AssignedLicenses.Report('assignedDateTime')

```

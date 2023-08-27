# GetLicenseInfo
Simple module that retrieves information about liceses assigned to user account and can display it as formatted report.

Module retrieves list of licenses subscribed by a tenant, plus retrieves recent list of product and SKU display names from Microsoft. 
Module then uses downloaded display names to enrich the output.

When multiple users returned, users without any license are automatically filtered out to speed up the processing

# Usage
Sample below shows various uses of the module.

## License info for single user
```powershell
#get license info about user, explicitly specifying tenant ID and authenticating transparently va Windows Authentication Manager
Connect-LicenseTenant -TenantId mydomain.com -AuthMode Wam
$user = Get-LicenseInfo -UserPrincipalName user@mydomain.com
$user | select-object -Expand AssignedLicenses
```

## License info for single user with report
```powershell
#get license info about user. Command creates license report
Connect-LicenseTenant -TenantId mydomain.com -AuthMode Wam
$user = Get-LicenseInfo -UserPrincipalName user@mydomain.com -CreateReport
#display assigned licenses
$user.AssignedLicenses

#display license report, sorted by display name
$user.AssignedLicenses.Report()
```

## License info for multiple users
```powershell
#get license info about all users whose UPN starts with 'a', showing progress
Connect-LicenseTenant -TenantId mydomain.com -AuthMode Interactive
Get-LicenseInfo -UpnStartsWith a -ShowProgress | select-object -expand AssignedLicenses
```

## License info for multiple users with limited license set returned
```powershell
#get license info about all users whose UPN starts with 'a', authenticating with client id a client secret
Connect-LicenseTenant -TenantId mydomain.com -ClientId $myClientId -ClientSecret $myClientSecret
Get-LicenseInfo -UpnStartsWith a -IncludedSkus @('SPE_E3','SPE_E5') | select-object -expand AssignedLicenses
```

## Complete license info for all users in tenant
```powershell
Connect-LicenseTenant -TenantId mydomain.com -ClientId $myClientId -ClientSecret $myClientSecret
Get-LicenseInfo -ShowProgress
```

## Complete license info for all users in tenant with user information in each license
```powershell
Connect-LicenseTenant -TenantId mydomain.com -AuthMode Interactive
Get-LicenseInfo -ShowProgress -CreateReport | foreach-object{$_.AssignedLicenses.Report()}
```

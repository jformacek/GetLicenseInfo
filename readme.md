# GetLicenseInfo
Simple module that retrieves information about liceses assigned to user account and can display it as formatted report.

Module retrieves list of licenses subscribed by a tenant, plus retrieves recent list of product and SKU display names from Microsoft. Module then uses downloaded display names to enrich the output.

When multiple users returned, users without any license are automatically filtered out to speed up the processing

# Usage
Sample below shows various uses of the module.

## License info for single user
```powershell
#get license info about user, explicitly specifying tenant ID
$user = Get-LicenseInfo -UserPrincipalName user@domain.com -TenantId $domain.com
```

## License info for single user with auto-detected tenant id
```powershell
#get license info about user. Command will detect tenant ID from domain part of userPrincipalName
$user = Get-LicenseInfo -UserPrincipalName user@domain.com
```

## License info for single user with auto-detected tenant id
```powershell
#get license info about user. Command will detect tenant ID from domain part of userPrincipalName
$user = Get-LicenseInfo -UserPrincipalName user@domain.com -CreateReport
#display assigned licenses
$user.AssignedLicenses

#display license report, sorted by display name
$user.AssignedLicenses.Report()
```

## License info for multiple users
```powershell
#get license info about all users whose UPN starts with 'a', showing progress
$users = Get-LicenseInfo -TenantId mydomain.com -UpnStartsWith a -ShowProgress
$user.AssignedLicenses
```

## License info for multiple users with limited license set returned
```powershell
#get license info about all users whose UPN starts with 'a', showing progress
$users = Get-LicenseInfo -TenantId mydomain.com -UpnStartsWith a -ShowProgress -IncludedSkus @('SPE_E3','SPE_E5')
$user.AssignedLicenses
```

## Complete license info for all users in tenant
```powershell
Get-LicenseInfo -TenantId mydomain.com -ShowProgress
```

## Complete license info for all users in tenant with user information in each license
```powershell
Get-LicenseInfo -TenantId mydomain.com -ShowProgress -IncludeUpnInAssignedLicenses
```

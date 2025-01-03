#region Public commands
function Connect-LicenseTenant
{
    <#
.SYNOPSIS
    Sets up the connection to tenant

.DESCRIPTION
    Sets up connection parameters to tenant (and to internet)

.OUTPUTS
    List of tenants already connected to, along with authentication provider
#>

    param
    (
        [Parameter(ParameterSetName = 'PublicClient')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithSecret')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithCertificate')]
        [string]
            #Id of tenant where to autenticate the user. Can be tenant id, or any registerd DNS domain
            #Not necessary when connecting with Managed Identity, otherwise ncesessary
        $TenantId,

        [Parameter()]
        [string]
            #ClientId of application that gets token to Graph API.
            #Default: well-known clientId for Azure PowerShell
        $ClientId = (Get-AadDefaultClientId),

        [Parameter()]
        [Uri]
            #RedirectUri for the client
            #Default: default MSAL redirect Uri
        $RedirectUri,

        [Parameter(ParameterSetName = 'ConfidentialClientWithSecret')]
        [string]
            #Client secret for ClientID
            #Used to get access as application rather than as calling user
        $ClientSecret,

        [Parameter(ParameterSetName = 'ConfidentialClientWithCertificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
            #Authentication certificate for ClientID
            #Used to get access as application rather than as calling user
        $X509Certificate,

        [Parameter()]
        [string]
            #AAD auth endpoint
            #Default: endpoint for public cloud
        $LoginApi = 'https://login.microsoftonline.com',
        
        [Parameter(Mandatory, ParameterSetName = 'PublicClient')]
        [ValidateSet('Interactive', 'DeviceCode', 'WIA', 'WAM')]
        [string]
            #How to authenticate client
        $AuthMode,
        
        [Parameter(ParameterSetName = 'PublicClient')]
        [string]
            #Username hint for interactive authentication flows
        $UserNameHint,

        [Parameter(ParameterSetName = 'MSI')]
        [Switch]
            #tries to get parameters from environment and token from internal endpoint provided by Azure MSI support
        $UseManagedIdentity,

        [Parameter(ParameterSetName = 'ExistingFactory')]
        [object]
            #Existing factory to use rather than create a new one
        $Factory,

        [Parameter()]
        [System.Net.WebProxy]
            #Proxy configuration for cases when internet is begind proxy
        $Proxy
    )

    process
    {
        if($null -ne $proxy)
        {
            [system.net.webrequest]::defaultwebproxy = $proxy
        }
        try {
                switch($PSCmdlet.ParameterSetName)
                {
                    'PublicClient' {
                        $script:AuthFactory = New-AadAuthenticationFactory -TenantId $TenantId -ClientId $ClientId -RedirectUri $RedirectUri -LoginApi $LoginApi -AuthMode $AuthMode -DefaultUsername $UserNameHint
                        break;
                    }
                    'ConfidentialClientWithSecret' {
                        $script:AuthFactory = New-AadAuthenticationFactory -TenantId $TenantId -ClientId $ClientId -RedirectUri $RedirectUri -ClientSecret $clientSecret -LoginApi $LoginApi
                        break;
                    }
                    'ConfidentialClientWithCertificate' {
                        $script:AuthFactory = New-AadAuthenticationFactory -TenantId $TenantId -ClientId $ClientId -X509Certificate $X509Certificate -LoginApi $LoginApi
                        break;
                    }
                    'MSI' {
                        $script:AuthFactory = New-AadAuthenticationFactory -ClientId $clientId -UseManagedIdentity
                        break;
                    }
                    'ExistingFactory' {
                        $script:AuthFactory = $Factory
                        break;
                    }
                }
                $script:AuthFactory
        }
        catch {
            throw
        }
    }
}
Function Get-LicenseInfo
{
<#
.SYNOPSIS
    Command retrieves license information for user

.DESCRIPTION
    Command retrieves license information for user and prepares formatted report. Command makes use of diplay names of products and licenses published by Microsoft as separate downloadable.

.LINK
    https://github.com/jformacek/GetLicenseInfo

.EXAMPLE
$user = Get-LicenseInfo -UserPrincipalName user@domain.com -TenantId $domain.com
#display assigned licenses
$user.AssignedLicenses

Command above retrieves licenses for given user and shows them

.EXAMPLE
$user = Get-LicenseInfo -UserPrincipalName user@domain.com -TenantId $domain.com
#display license report, sorted by assigned time
$user.AssignedLicenses.Report('assignedDateTime')

Command above retrieves licenses for given user and shows them as report, sorted by SKU assigned date

.EXAMPLE
$users = Get-LicenseInfo -TenantId mydomain.com -UpnStartsWith a -ShowProogress
$user.AssignedLicenses

Command above gets and shows license info about all users whose UPN starts with 'a', showing progress
#>
[CmdletBinding()]
param
    (
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='SingleUser')]
        [ValidateScript({$_ -match '@'})]
        [string]
        #UPN of user. Multiple UPNs can be sent from pipeline
        $UserPrincipalName,
        [Parameter(ParameterSetName='MultipleUsers')]
        [int]
        #page size for graph api call
        $BatchSize = 100,
        [Parameter(ParameterSetName='MultipleUsers')]
        [string]
        #limit number of returned users by specifying beginning of UPN
        $UpnStartsWith,
        [switch]
        #whether to define Report() function on assigned licenses on user
        $CreateReport,
        [switch]
        #whether to show progress UI
        $ShowProgress,
        [switch]
        #whether each assigned license sku shall also contain Upn of owning user
        $IncludeUpnInAssignedLicenses,
        #only process SKUs in the list (SKU id or SKU displayName)
        [string[]]$IncludedSkus=@(),
        #omit SKUs in the list (SKU id or SKU displayName) from results
        [string[]]$ExcludedSkus=@()
    )

    begin
    {

        switch($PsCmdlet.ParameterSetName)
        {
            'MultipleUsers' {
                if($BatchSize -gt 999 -or $BatchSize -lt 1)
                {
                    throw 'BatchSize must be between 1 and 999'
                }
                break;
            }
        }

        if($null -eq $script:prods) {$script:prods = Get-ProductTable}

        if($null -eq $script:orgSkus)
        {
            $script:orgSkus = Get-SubscribedSkus
        }
        if($IncludedSkus.Count -gt 0)
        {
            $orgSubscribedSkus = $script:orgSkus.Where{($_.skuId -in $IncludedSkus) -or ($_.skuPartNumber -in $IncludedSkus)}
        }
        else
        {
            if($ExcludedSkus.Count -gt 0)
            {
                $orgSubscribedSkus = $script:orgSkus.Where{($_.skuId -notin $ExcludedSkus) -or ($_.skuPartNumber -notin $ExcludedSkus)}
            }
            else
            {
                $orgSubscribedSkus = $script:orgSkus
            }
        }
    }

    process
    {
        switch($PsCmdlet.ParameterSetName)
        {
            'SingleUser' {
                $user = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/users/$UserPrincipalName`?`$select=id,userPrincipalName,assignedLicenses,assignedPlans" `
                    -Headers (Get-AadToken -AsHashTable -Factory $script:authFactory -Scopes 'https://graph.microsoft.com/.default')
                $user | ProcessUser -orgSubscribedSkus $orgSubscribedSkus -CreateReport $CreateReport -IncludeUpnInAssignedLicenses $IncludeUpnInAssignedLicenses
                break;
            }
            'MultipleUsers' {
                if([string]::IsNullOrWhiteSpace($UpnStartsWith))
                {
                    $Uri = "https://graph.microsoft.com/v1.0/users`?`$select=id,userPrincipalName,assignedLicenses,assignedPlans`&`$filter=assignedLicenses/`$count ne 0`&`$count=true`&`$top=$BatchSize"
                }
                else
                {
                    $Uri = "https://graph.microsoft.com/v1.0/users`?`$select=id,userPrincipalName,assignedLicenses,assignedPlans`&`$filter=startsWith(userPrincipalName,'$UpnStartsWith') and assignedLicenses/`$count ne 0`&`$count=true`&`$top=$BatchSize"
                }
                $total = 0
                $current = 0
                do
                {
                    $headers = Get-AadToken -AsHashTable -Factory $script:authFactory -Scopes 'https://graph.microsoft.com/.default'
                    $headers['ConsistencyLevel'] = 'eventual'
                    $data = Invoke-RestMethod -Uri $Uri -Headers $headers
                    if($null -ne $data.'@odata.count')
                    {
                        $total = $data.'@odata.count'
                    }
                    $current+=$data.value.count
                    if($ShowProgress)
                    {
                        Write-Progress -Activity 'Processing' -Status "$current / $total " -PercentComplete ([int]($current * 100 / $total))
                    }
                    $data.value | ProcessUser -orgSubscribedSkus $orgSubscribedSkus -CreateReport $CreateReport -IncludeUpnInAssignedLicenses $IncludeUpnInAssignedLicenses
                    $Uri = $data.'@odata.nextLink'
                }while($null -ne $Uri)
                if($ShowProgress)
                {
                    Write-Progress -Activity 'Processing' -Completed
                }
                break;
            }
        }
    }
}
function Get-TenantSubscribedLicense
{
    begin
    {
        if($null -eq $script:prods) {$script:prods = Get-ProductTable}

        if($null -eq $script:orgSkus)
        {
            $script:orgSkus = Get-SubscribedSkus
        }
    }
    process
    {
        $script:orgSkus
    }
}
#endregion Public commands
#region Internal commands
Function Get-ProductTable
{
    param()

    begin
    {
        #see https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
        $uri = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
    }
    process
    {
        $tree = @{}
        $rsp = Invoke-WebRequest -Uri $uri
        $displayNamesTable = [System.Text.Encoding]::UTF8.GetString($rsp.Content) | ConvertFrom-Csv -Delimiter ','
        foreach($descriptor in $displayNamesTable)
        {
            if($null -eq $tree[$descriptor.GUID])
            {
                $tree[$descriptor.GUID] = @{
                    Name = $descriptor.String_Id
                    DisplayName = $descriptor.Product_Display_Name
                    Description = "$($descriptor.Product_Display_Name) ($($descriptor.String_Id))"
                    Plans = @{}
                }
            }
            $product = $tree[$descriptor.GUID]
            if($null -eq $product.Plans[$descriptor.Service_Plan_Id])
            {
                $product.Plans[$descriptor.Service_Plan_Id] = @{
                    Name = $descriptor.Service_Plan_Name
                    DisplayName = $descriptor.Service_Plans_Included_Friendly_Names
                    Description = "$($descriptor.Service_Plans_Included_Friendly_Names) ($($descriptor.Service_Plan_Name))"
                }
            }
        }
        $tree
    }
}
function Get-SubscribedSkus
{
    process
    {
        if($null -eq $script:AuthFactory)
        {
            throw "Please call 'Connect-LicenseTenant' first"
        }
        $rsp = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -Headers (Get-AadToken -AsHashTable -Factory $script:authFactory -Scopes 'https://graph.microsoft.com/.default')
        $rsp.value | ForEach-Object {
            $name = ($script:prods[$_.skuId]).Name
            $displayName = ($script:prods[$_.skuId]).DisplayName
            if([string]::IsNullOrEmpty($displayName))
            {
                $displayName = $_.skuPartNumber
            }
            if([string]::IsNullOrEmpty($name))
            {
                $Name = $_.skuPartNumber
            }

            $_ | Add-Member -MemberType NoteProperty -Name DisplayName -Value $displayName -PassThru `
                | Add-Member -MemberType NoteProperty -Name Name -Value $name
        }
        $rsp.Value
    }
}
function ProcessUser
{
    param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [PSCustomObject]$graphUser,
        [Parameter(Mandatory)]
        $orgSubscribedSkus,
        [Parameter(Mandatory)]
        [bool]$CreateReport,
        [bool]$IncludeUpnInAssignedLicenses
    )

    process
    {
        $user = [PSCustomObject]@{
            UserPrincipalName = $graphUser.userPrincipalName
            Id = $graphUser.id
            AssignedLicenses = $graphUser.assignedLicenses.Where{$_.skuId -in $orgSubscribedSkus.skuId}
        }
        foreach($sku in $user.assignedLicenses)
        {
            $sku `
            | Add-Member -MemberType NoteProperty -Name AssignedServices -Value @() -PassThru `
            | Add-Member -MemberType NoteProperty -Name AssignedDate -Value ([DateTime]::MaxValue) -PassThru `
            | Add-Member -MemberType NoteProperty -Name Name -Value ($script:prods[$sku.skuId]).Name -PassThru `
            | Add-Member -MemberType NoteProperty -Name DisplayName -Value ($script:prods[$sku.skuId]).DisplayName
            if($CreateReport)
            {
                $sku | Add-Member -MemberType ScriptMethod -Name Report -Value {
                    param( [string]$Sort = "DisplayName")
                    $marker = [char]27
                    $bold = "$marker[1m"
                    $underline = "$marker[4m"
                    $resetChanges = "$marker[0m"
                    $header = $bold + $underline
                    if(-not [string]::IsNullOrEmpty($this.userPrincipalName)) {$header+="$($this.UserPrincipalName)`t"}
                    $header+="$($this.Name)`t$($this.DisplayName)`t$($this.AssignedDate)"
                    $header+=$resetChanges
                    $header
                    ($this.AssignedServices | Sort-Object $Sort | Format-Table displayName, assignedDateTime, capabilityStatus)
                }
            }
            if($IncludeUpnInAssignedLicenses)
            {
                $sku | Add-Member -MemberType NoteProperty -Name UserPrincipalName -Value $User.UserPrincipalName
            }

            if([string]::IsNullOrEmpty($sku.Name))
            {
                #name not published in downloadable CSV - fallback
                $sku.Name = ($orgSubscribedSkus | Where-Object{$_.skuId -eq $sku.skuId}).SkuPartNumber
            }
            if([string]::IsNullOrEmpty($sku.DisplayName))
            {
                $sku.DisplayName = $sku.Name
            }
        }
    
        $userAssignedSkus = $orgSubscribedSkus.Where{$_.skuId -in $user.assignedLicenses.skuId}
        foreach($plan in $graphUser.assignedPlans)
        {
            if($plan.psobject.properties.name -notcontains 'displayName')
            {
                $plan | Add-Member -MemberType NoteProperty -Name displayName -Value $null
            }
            #user may have multiple products assigned containing the same plan
            foreach($sku in $userAssignedSkus.Where{$_.servicePlans.servicePlanId -eq $plan.servicePlanId})
            {
                if($null -ne $script:prods[$sku.skuId])
                {
                    $plan.displayName = $script:prods[$sku.skuId].Plans[$plan.servicePlanId].DisplayName
                }
                else
                {
                    #display name not published in downloadable CSV - fallback
                    $plan.displayName = ($sku.servicePlans | Where-Object{$_.servicePlanId -eq $plan.servicePlanId}).ServicePlanName
                }
                foreach($userSku in $user.assignedLicenses.Where{$_.skuId -eq $sku.skuId})
                {
                    $userSku.AssignedServices+=$plan
                    #PS 5 may not parse datetime out of box
                    if($plan.assignedDateTime -is [string]) {$plan.assignedDateTime = [DateTime]::Parse($plan.assignedDateTime)}
                    if($plan.assignedDateTime -lt $userSku.AssignedDate)
                    {
                        $userSku.AssignedDate = $plan.assignedDateTime
                    }
                }
            }
        }
        $user
    }
}
#endregion Internal commands
#region Module initialization
if($null -eq 'TrustAllCertsPolicy' -as [type])
{
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@    
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion Module initialization

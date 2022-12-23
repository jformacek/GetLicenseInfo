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
        [Parameter()]
        [string]
        #Tenant Id. If not specified, domain part of UPN is used as tenant id
        $TenantId,
        [Parameter(ParameterSetName='MultipleUsers')]
        [int]
        #page size for graph api call
        $BatchSize = 100,
        [Parameter(ParameterSetName='MultipleUsers')]
        [string]
        #limit number of returned users by specifying beginning of UPN
        $UpnStartsWith,
        [Parameter()]
        [ValidateSet('Interactive','DeviceCode','WIA')]
        #type of authentication
        $AuthMode='Interactive',
        [switch]
        #whether to define Report() function on assigned licenses on user
        $CreateReport,
        [switch]
        #whether to show progress UI
        $ShowProgress
    )

    begin
    {
        switch($PsCmdlet.ParameterSetName)
        {
            'SingleUser' {
                if([string]::IsNullOrWhiteSpace($TenantId))
                {
                    $TenantId = $UserPrincipalName.Split('@')[1]
                }
                break;
            }
            'MultipleUsers' {
                if([string]::IsNullOrWhiteSpace($TenantId))
                {
                    throw 'Tenant ID must be specified'
                }
                if($BatchSize -gt 999 -or $BatchSize -lt 1)
                {
                    throw 'BatchSize must be between 1 and 999'
                }
                break;
            }
        }

        if($null -eq $script:authFactories[$TenantId]) {
            $script:authFactories[$TenantId] = New-AadAuthenticationFactory -TenantId $TenantId -RequiredScopes 'https://graph.microsoft.com/.default' -AuthMode Interactive
        }
        $rsp = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -Headers (Get-AadToken -AsHashTable -Factory $script:authFactories[$TenantId])
        $orgSubscribedSkus = $rsp.Value
    }

    process
    {
        switch($PsCmdlet.ParameterSetName)
        {
            'SingleUser' {
                $user = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/users/$UserPrincipalName`?`$select=id,userPrincipalName,assignedLicenses,assignedPlans" `
                    -Headers (Get-AadToken -AsHashTable -Factory $script:authFactories[$TenantId])
                $user | ProcessUser -orgSubscribedSkus $orgSubscribedSkus -CreateReport $CreateReport
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
                    $headers = Get-AadToken -AsHashTable -Factory $script:authFactories[$TenantId]
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
                    foreach($user in $data.value)
                    {
                        $user | ProcessUser -orgSubscribedSkus $orgSubscribedSkus -CreateReport $CreateReport
                    }
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

function ProcessUser
{
    param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        $graphUser,
        [Parameter(Mandatory)]
        $orgSubscribedSkus,
        [Parameter(Mandatory)]
        [bool]$CreateReport
    )

    process
    {
        $user = [PSCustomObject]@{
            UserPrincipalName = $graphUser.userPrincipalName
            Id = $graphUser.id
            AssignedLicenses = $graphUser.assignedLicenses
        }
        foreach($sku in $user.assignedLicenses)
        {
            $sku `
            | Add-Member -MemberType NoteProperty -Name AssignedServices -Value @() -PassThru `
            | Add-Member -MemberType NoteProperty -Name AssignedDate -Value ([DateTime]::MaxValue) -PassThru `
            | Add-Member -MemberType NoteProperty -Name Name -Value ($script:prods[$sku.skuId]).Name -PassThru `
            | Add-Member -MemberType NoteProperty -Name DisplayName -Value ($script:prods[$sku.skuId]).DisplayName -PassThru
            if($CreateReport)
            {
                $sku | Add-Member -MemberType ScriptMethod -Name Report -Value {
                    param( [string]$Sort = "DisplayName")
                    $marker = [char]27
                    $bold = "$marker[1m"
                    $underline = "$marker[4m"
                    $resetChanges = "$marker[0m"
            
                    $bold + $underline + "$($this.Name)`t$($this.DisplayName)`t$($this.AssignedDate)" + $resetChanges
                    ($this.AssignedServices | Sort-Object $Sort | Format-Table displayName, assignedDateTime, capabilityStatus)
                }
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
            $plan | Add-Member -MemberType NoteProperty -Name displayName -Value $null
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
if($null -eq $script:prods) {$script:prods = Get-ProductTable}
$script:authFactories = @{}

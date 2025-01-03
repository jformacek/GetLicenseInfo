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

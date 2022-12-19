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
    param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$UserPrincipalName,
        [Parameter()]
        [string]$TenantId = $UserPrincipalName.Split('@')[1]
    )

    begin
    {
        if($null -eq $script:authFactories[$TenantId]) {$script:authFactories[$TenantId] = New-AadAuthenticationFactory -TenantId $TenantId -RequiredScopes 'https://graph.microsoft.com/.default' -AuthMode Interactive}
        $rsp = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -Headers (Get-AadToken -AsHashTable -Factory $script:authFactories[$TenantId])
        $orgSubscribedSkus = $rsp.Value
    }

    process
    {
        $data = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserPrincipalName`?`$select=id,assignedLicenses,assignedPlans" -Headers (Get-AadToken -AsHashTable -Factory $script:authFactories[$TenantId])
        $user = [PSCustomObject]@{
            UserPrincipalName = $UserPrincipalName
            Id = $data.id
            AssignedLicenses = $data.assignedLicenses
        }
        foreach($sku in $user.assignedLicenses)
        {
            $sku `
            | Add-Member -MemberType NoteProperty -Name AssignedServices -Value @() -PassThru `
            | Add-Member -MemberType NoteProperty -Name AssignedDate -Value ([DateTime]::MaxValue) -PassThru `
            | Add-Member -MemberType NoteProperty -Name Name -Value ($prods[$sku.skuId]).Name -PassThru `
            | Add-Member -MemberType NoteProperty -Name DisplayName -Value ($prods[$sku.skuId]).DisplayName -PassThru `
            | Add-Member -MemberType ScriptMethod -Name Report -Value {
                $marker = [char]27
                $bold = "$marker[1m"
                $underline = "$marker[4m"
                $resetChanges = "$marker[0m"
        
                $bold + $underline + "$($this.Name)`t$($this.DisplayName)`t$($this.AssignedDate)" + $resetChanges
                ($this.AssignedServices | Format-Table)
            }
        }
    
        $userAssignedSkus = $orgSubscribedSkus.Where{$_.skuId -in $user.assignedLicenses.skuId}
        foreach($plan in $data.assignedPlans)
        {
            $plan | Add-Member -MemberType NoteProperty -Name displayName -Value $null
            #user may have multiple products assigned containing the same plan
            foreach($sku in $userAssignedSkus.Where{$_.servicePlans.servicePlanId -eq $plan.servicePlanId})
            {
                $plan.displayName = $prods[$sku.skuId].Plans[$plan.servicePlanId].DisplayName
                foreach($userSku in $user.assignedLicenses.Where{$_.skuId -eq $sku.skuId})
                {
                    $userSku.AssignedServices+=$plan
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

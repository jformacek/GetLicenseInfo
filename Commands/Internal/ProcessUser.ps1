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

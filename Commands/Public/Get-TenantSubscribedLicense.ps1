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

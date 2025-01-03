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

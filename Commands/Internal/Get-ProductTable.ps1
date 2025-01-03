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

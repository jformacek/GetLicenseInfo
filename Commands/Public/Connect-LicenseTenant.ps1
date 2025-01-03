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

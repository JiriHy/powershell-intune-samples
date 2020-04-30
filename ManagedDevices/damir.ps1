function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
        
        if ($AadModule -eq $null) {
            
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
        
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }
function Get-Token ($tenant, $grantType, $clientId, $clientSecret)
{
    #$resource = "00000002-0000-0000-c000-000000000000" # used for GRAPH
    $resource = "https://management.azure.com/"

    $data = @{
            "grant_type"    = $grantType
            "client_id"     = $clientId
            "client_secret" = $clientSecret
            "resource"      = $resource
            }

    $headers = @{
            #
            "ContentType" = "application/json"
            "cache-control" = "no-cache"
            }

    $params = @{
            body    = $data
            Headers = $headers
            Method  = 'Post'
            URI     = "https://login.microsoftonline.com/$tenant/oauth2/token"
        }

    $response = Invoke-RestMethod @params
    #$response
    return $response.access_token
}
function Get-Rest($uri, $token)
{

    $params = @{
        ContentType = 'application/json'
        Headers     = @{
            'authorization' = "Bearer $($token)"
        }
        Method      = 'Get'
        URI         = $uri
    }
    #endregion

    #region execute rest and wait for response
    try
    {
        # With "Invoke-RestMethod" there is no answer returned to check for StatusCode
        $response = Invoke-RestMethod @params
        return $response
    }
    catch
    {
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Write-Host $Error[0] -ForegroundColor Yellow
        break
    }
}

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}




$tenant = $env:AZURE_TENANT_IDW
$grantType = "client_credentials"
$clientId = $env:AZURE_CLIENT_IDW
$clientSecret = $env:AZURE_CLIENT_SECRETW

$token = Get-Token -tenant $tenant -grantType $grantType -clientId $clientId -clientSecret $clientSecret

$greater_ThanTimeStamp = Read-Host "From (yyyy-MM-ddThh:mm:ss.ssssZ)"#"2019-01-30T01:41:48Z"
$less_ThanTimestamp = Read-Host "To(yyyy-MM-ddThh:mm:ss.ssssZ)"#"2019-02-01T17:00:00Z"

$retVal = @()

$baseURI = "https://management.azure.com/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$"
$filterURI = "filter=eventTimestamp ge '$($greater_ThanTimeStamp)' and eventTimestamp le '$($less_ThanTimestamp)' and eventChannels eq 'Operation' and resourceProvider eq 'Microsoft.Management'"

$uri = "$($baseURI)$($filterUri)"
    $uri
$resp = Get-Rest -token $token -uri $uri
$retVal += $resp

if($resp.NextLink)
{
    while($resp.nextLink)
    {
        $resp = Get-Rest -token $token -uri $resp.nextLink
        $retVal += $resp
    }
    <#
    $retVal += Get-Next -nextLink resp.NextLink -token $token
    Get-Next -nextLink resp.NextLink -token $token
    #>
}

$retVal.Value `
        | ?{($_.authorization).scope -like "/providers/Microsoft.Management/managementGroups/*"} `
        | select @{l="scope";e={($_.authorization).scope}},eventTimestamp, @{l="operation";e={$_.operationname.localizedvalue}}, @{l="method";e={$_.httpRequest.method}}, caller `
        | Sort-Object eventTimestamp -Descending | ft *



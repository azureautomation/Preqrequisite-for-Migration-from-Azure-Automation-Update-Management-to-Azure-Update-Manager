<#
    .SYNOPSIS
    This script will carry out the prerequisites required for migration of machines and software update configurations from Azure Automation Update Management to Azure Update Manager.

    .DESCRIPTION
    This script will do the following:
    1. Retrieve all machines onboarded to Azure Automation Update Management under this automation account from linked log analytics workspace.
    2. Update the Az.Modules for the automation account.
    3. Creates an automation variable with name AutomationAccountAzureEnvironment which will store the Azure Cloud Environment to which Automation Account belongs.
    4. Create user managed identity in the same subscription and resource group as the automation account.
    5. Associate the user managed identity to the automation account.
    6. Assign required roles to the user managed identity created.

    The executor of the script should have Microsoft.Authorization/roleAssignments/write action such as Role Based Access Control Administrator on the scopes on which access will be granted to user managed identity. 
    The script will register the automation subscription, subscriptions to which machines belong and subscriptions in dynamic azure queries to Microsoft.Maintenance and hence executor of the script should have Contributor/Owner access to all those subscriptions.
    The script will register the automation subscription to Microsoft.EventGrid and hence executor of the script should have Contributor/Owner access to the subscription.

    .PARAMETER AutomationAccountResourceId
        Mandatory
        Automation Account Resource Id.

    .PARAMETER AutomationAccountAzureEnvironment
        Mandatory
        Azure Cloud Environment to which Automation Account belongs.
        Accepted values are AzureCloud, AzureUSGovernment, AzureChinaCloud.
        
    .EXAMPLE
        MigrationPrerequisites -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}" -AutomationAccountAzureEnvironment "AzureCloud"

    .OUTPUTS
        The user managed identity with required role assignments.
#>
param(

    [Parameter(Mandatory = $true)]
    [String]$AutomationAccountResourceId,

    [Parameter(Mandatory = $true)]
    [String]$AutomationAccountAzureEnvironment = "AzureCloud"
)

# Telemetry level.
$Debug = "Debug"
$Verbose = "Verbose" 
$Informational = "Informational"
$Warning = "Warning" 
$ErrorLvl = "Error"

$Succeeded = "Succeeded"
$Failed = "Failed"

# ARM resource types.
$VMResourceType = "virtualMachines";
$ArcVMResourceType = "machines";

# API versions.
$AutomationApiVersion = "2022-08-08"
$SoftwareUpdateConfigurationApiVersion = "2023-11-01";
$UserManagedIdentityApiVersion = "2023-01-31";
$AzureRoleAssignmentApiVersion = "2022-04-01";
$SolutionsApiVersion = "2015-11-01-preview"
$RegisterResourceProviderApiVersion = "2022-12-01";
$AutomationVariableApiVersion = "2023-11-01";

# HTTP methods.
$GET = "GET"
$PATCH = "PATCH"
$PUT = "PUT"
$POST = "POST"

# ARM endpoints.
$LinkedWorkspacePath = "{0}/linkedWorkspace"
$SoftwareUpdateConfigurationsPath = "{0}/softwareUpdateConfigurations?`$skip={1}"
$SolutionsWithWorkspaceFilterPath = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationsManagement/solutions?`$filter=properties/workspaceResourceId%20eq%20'{2}'"
$UserManagedIdentityPath = "subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{2}"
$AzureRoleDefinitionPath = "/providers/Microsoft.Authorization/roleDefinitions/{0}"
$AzureRoleAssignmentPath = "{0}/providers/Microsoft.Authorization/roleAssignments/{1}"
$MaintenanceResourceProviderRegistrationPath = "/subscriptions/{0}/providers/Microsoft.Maintenance/register"
$EventGridResourceProviderRegistrationPath = "/subscriptions/{0}/providers/Microsoft.EventGrid/register"
$AutomationVariablePath = "{0}/variables/AutomationAccountAzureEnvironment"

# Role Definition IDs.
$AzureConnectedMachineOnboardingRole = "b64e21ea-ac4e-4cdf-9dc9-5b892992bee7"
$VirtualMachineContributorRole = "9980e02c-c2be-4d73-94e8-173b1dc7cf3c"
$LogAnalyticsContributorRole = "92aaf0da-9dab-42b6-94a3-d43ce8d16293"
$LogAnalyticsReaderRole = "73c42c96-874c-492b-b04d-ab87d138a893"
$AutomationOperatorRole = "d3881f73-407a-4167-8283-e981cbba0404"
$ScheduledPatchingContributorRole = "cd08ab90-6b14-449c-ad9a-8f8e549482c6"
$ContributorRole = "b24988ac-6180-42a0-ab88-20f7382dd24c"

# Validation values.
$TelemetryLevels = @($Debug, $Verbose, $Informational, $Warning, $ErrorLvl)
$HttpMethods = @($GET, $PATCH, $POST, $PUT)

#Max depth of payload.
$MaxDepth = 5

# Beginning of Payloads.

$AssignUserManagedIdentityToAutomationAccountPayload = @"
{
    "identity": {
      "type": "",
      "userAssignedIdentities": {
      }
    }
}
"@

$UserManagedIdentityCreationPayload = @"
{
  "location": "",
  "tags": {
  }
}
"@

$UpdateAzModulesPayload = @"
{
    "properties": {
      "RuntimeConfiguration": {
        "powershell": {
          "builtinModules": {
            "Az": "8.0.0"
          }
        }
      }
    }
}
"@

$RoleAssignmentPayload = @"
{
    "Id": "",
    "Properties": {
      "PrincipalId": "",
      "PrincipalType": "ServicePrincipal",
      "RoleDefinitionId": "",
      "Scope": ""
    }
  }  
"@

$AutomationVariablePayload = @"
{
    "name": "",
    "properties": {
      "value": "",
      "description": "Azure Cloud Environment for the Automation Account",
      "isEncrypted": false
    }
}
"@

# End of Payloads.

$MachinesOnboaredToAutomationUpdateManagementQuery = 'Heartbeat | where Solutions contains "updates" | distinct Computer, ResourceId, ResourceType, OSType'
$Global:Machines = [System.Collections.ArrayList]@()
$Global:AutomationAccountRegion = $null
$Global:UserManagedIdentityResourceId = $null
$Global:UserManagedIdentityPrincipalId = $null
$Global:SoftwareUpdateConfigurationsResourceIDs = @{}
$Global:AzureDynamicQueriesScope = @{}
$Global:SubscriptionsToRegisterToMaintenanceResourceProvider = @{}

function Write-Telemetry
{
    <#
    .Synopsis
        Writes telemetry to the job logs.
        Telemetry levels can be "Informational", "Warning", "Error" or "Verbose".
    
    .PARAMETER Message
        Log message to be written.
    
    .PARAMETER Level
        Log level.

    .EXAMPLE
        Write-Telemetry -Message Message -Level Level.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Message,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateScript({ $_ -in $TelemetryLevels })]
        [String]$Level = $Informational
    )

    if ($Level -eq $Warning)
    {
        Write-Warning $Message
    }
    elseif ($Level -eq $ErrorLvl)
    {
        Write-Error $Message
    }
    else
    {
        Write-Verbose $Message -Verbose
    }
}

function Parse-ArmId
{
    <#
        .SYNOPSIS
            Parses ARM resource id.
    
        .DESCRIPTION
            This function parses ARM id to return subscription, resource group, resource name, etc.
    
        .PARAMETER ResourceId
            ARM resourceId of the machine.      
    
        .EXAMPLE
            Parse-ArmId -ResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )

    $parts = $ResourceId.Split("/")
    return @{
        Subscription = $parts[2]
        ResourceGroup = $parts[4]
        ResourceProvider = $parts[6]
        ResourceType = $parts[7]
        ResourceName = $parts[8]
    }
}

function Invoke-RetryWithOutput
{
    <#
        .SYNOPSIS
            Generic retry logic.
    
        .DESCRIPTION
            This command will perform the action specified until the action generates no errors, unless the retry limit has been reached.
    
        .PARAMETER Command
            Accepts an Action object.
            You can create a script block by enclosing your script within curly braces.     
    
        .PARAMETER Retry
            Number of retries to attempt.
    
        .PARAMETER Delay
            The maximum delay (in seconds) between each attempt. The default is 5 seconds.
    
        .EXAMPLE
            $cmd = { If ((Get-Date) -lt (Get-Date -Second 59)) { Get-Object foo } Else { Write-Host 'ok' } }
            Invoke-RetryWithOutput -Command $cmd -Retry 61
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [ScriptBlock]$Command,
    
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Retry = 3,
    
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Delay = 5
    )
    
    $ErrorActionPreferenceToRestore = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
        
    for ($i = 0; $i -lt $Retry; $i++) 
    {
        $exceptionMessage = ""
        try 
        {            
            Write-Telemetry -Message ("[Debug]Command [{0}] started. Retry: {1}." -f $Command, ($i + 1) + $ForwardSlashSeparator + $Retry)
            $output = Invoke-Command $Command
            Write-Telemetry -Message ("[Debug]Command [{0}] succeeded." -f $Command) 
            $ErrorActionPreference = $ErrorActionPreferenceToRestore
            return $output
        }
        catch [Exception] 
        {
            $exceptionMessage = $_.Exception.Message
                
            if ($Global:Error.Count -gt 0) 
            {
                $Global:Error.RemoveAt(0)
            }

            if ($i -eq ($Retry - 1)) 
            {
                $message = ("[Debug]Command [{0}] failed even after [{1}] retries. Exception message:{2}." -f $command, $Retry, $exceptionMessage)
                Write-Telemetry -Message $message -Level $ErrorLvl
                $ErrorActionPreference = $ErrorActionPreferenceToRestore
                throw $message
            }

            $exponential = [math]::Pow(2, ($i + 1))
            $retryDelaySeconds = ($exponential - 1) * $Delay  # Exponential Backoff Max == (2^n)-1
            Write-Telemetry -Message ("[Debug]Command [{0}] failed. Retrying in {1} seconds, exception message:{2}." -f $command, $retryDelaySeconds, $exceptionMessage) -Level $Warning
            Start-Sleep -Seconds $retryDelaySeconds
        }
    }
}

function Invoke-AzRestApiWithRetry
{
   <#
        .SYNOPSIS
            Wrapper around Invoke-AzRestMethod.
    
        .DESCRIPTION
            This function calls Invoke-AzRestMethod with retries.
    
        .PARAMETER Params
            Parameters to the cmdlet.

        .PARAMETER Payload
            Payload.

        .PARAMETER Retry
            Number of retries to attempt.
    
        .PARAMETER Delay
            The maximum delay (in seconds) between each attempt. The default is 5 seconds.
            
        .EXAMPLE
            Invoke-AzRestApiWithRetry -Params @{SubscriptionId = "xxxx" ResourceGroup = "rgName" ResourceName = "resourceName" ResourceProvider = "Microsoft.Compute" ResourceType = "virtualMachines"} -Payload "{'location': 'westeurope'}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [System.Collections.Hashtable]$Params,

        [Parameter(Mandatory = $false, Position = 2)]
        [Object]$Payload = $null,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Retry = 3,
    
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Delay = 5
    )

    if ($Payload)
    {
        [void]$Params.Add('Payload', $Payload)
    }

    $retriableErrorCodes = @(429)
        
    for ($i = 0; $i -lt $Retry; $i++)
    {
        $exceptionMessage = ""
        $paramsString = $Params | ConvertTo-Json -Compress -Depth $MaxDepth | ConvertFrom-Json
        try
        {
            Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod started with params [{0}]. Retry: {1}." -f $paramsString, ($i+1) + $ForwardSlashSeparator + $Retry)
            $output = Invoke-AzRestMethod @Params -ErrorAction Stop
            $outputString = $output | ConvertTo-Json -Compress -Depth $MaxDepth | ConvertFrom-Json
            if ($retriableErrorCodes.Contains($output.StatusCode) -or $output.StatusCode -ge 500)
            {
                if ($i -eq ($Retry - 1))
                {
                    $message = ("[Debug]Invoke-AzRestMethod with params [{0}] failed even after [{1}] retries. Failure reason:{2}." -f $paramsString, $Retry, $outputString)
                    Write-Telemetry -Message $message -Level $ErrorLvl
                    return Process-ApiResponse -Response $output
                }

                $exponential = [math]::Pow(2, ($i+1))
                $retryDelaySeconds = ($exponential - 1) * $Delay  # Exponential Backoff Max == (2^n)-1
                Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] failed with retriable error code. Retrying in {1} seconds, Failure reason:{2}." -f $paramsString, $retryDelaySeconds, $outputString) -Level $Warning
                Start-Sleep -Seconds $retryDelaySeconds
            }
            else
            {
                Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] succeeded. Output: [{1}]." -f $paramsString, $outputString)
                return Process-ApiResponse -Response $output
            }
        }
        catch [Exception]
        {
            $exceptionMessage = $_.Exception.Message
            Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] failed with an unhandled exception: {1}." -f $paramsString, $exceptionMessage) -Level $ErrorLvl
            throw
        }
    }   
}

function Invoke-ArmApi-WithPath
{
   <#
        .SYNOPSIS
            The function prepares payload for Invoke-AzRestMethod
    
        .DESCRIPTION
            This function prepares payload for Invoke-AzRestMethod.
    
        .PARAMETER Path
            ARM API path.

        .PARAMETER ApiVersion
            API version.

        .PARAMETER Method
            HTTP method.

        .PARAMETER Payload
            Paylod for API call.
    
        .EXAMPLE
            Invoke-ArmApi-WithPath -Path "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Compute/virtualMachines/{vmName}/start" -ApiVersion "2023-03-01" -method "PATCH" -Payload "{'location': 'westeurope'}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Path,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$ApiVersion,

        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateScript({ $_ -in $HttpMethods })]
        [String]$Method,

        [Parameter(Mandatory = $false, Position =4)]
        [Object]$Payload = $null
    )

    $PathWithVersion = "{0}?api-version={1}"
    if ($Path.Contains("?"))
    {
        $PathWithVersion = "{0}&api-version={1}"
    }

    $Uri = ($PathWithVersion -f $Path, $ApiVersion) 
    $Params = @{
        Path = $Uri
        Method = $Method
    }

    return Invoke-AzRestApiWithRetry -Params $Params -Payload $Payload   
}

function Process-ApiResponse
{
    <#
        .SYNOPSIS
            Process API response and returns data.
    
        .PARAMETER Response
            Response object.
    
        .EXAMPLE
            Process-ApiResponse -Response {"StatusCode": 200, "Content": "{\"properties\": {\"location\": \"westeurope\"}}" }
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [Object]$Response
    )

    $content = $null
    if ($Response.Content)
    {
        $content = ConvertFrom-Json $Response.Content
    }

    if ($Response.StatusCode -eq 200)
    {
        return @{ 
            Status = $Succeeded
            Response = $content
            ErrorCode = [String]::Empty 
            ErrorMessage = [String]::Empty
            }
    }
    else
    {
        $errorCode = $Unknown
        $errorMessage = $Unknown
        if ($content.error)
        {
            $errorCode = ("{0}/{1}" -f $Response.StatusCode, $content.error.code)
            $errorMessage = $content.error.message
        }

        return @{ 
            Status = $Failed
            Response = $content
            ErrorCode = $errorCode  
            ErrorMessage = $errorMessage
            }
    }
}

function Get-MachinesFromLogAnalytics
{
   <#
        .SYNOPSIS
            Gets machines onboarded to updates solution from Log Analytics workspace.
    
        .DESCRIPTION
            This command will return machines onboarded to UM from LA workspace.

        .PARAMETER ResourceId
            Resource Id.

        .EXAMPLE
            Get-MachinesFromLogAnalytics -ResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )
    
    $armComponents = Parse-ArmId -ResourceId $ResourceId
    $script = {
        Set-AzContext -Subscription $armComponents.Subscription
        $Workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $armComponents.ResourceGroup -Name $armComponents.ResourceName
        $QueryResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $Workspace.CustomerId -Query $MachinesOnboaredToAutomationUpdateManagementQuery -ErrorAction Stop
        return $QueryResults
    }

    $output = Invoke-RetryWithOutput -command $script
    return $output  
}

function Populate-AllMachinesOnboardedToUpdateManagement
{
    <#
        .SYNOPSIS
            Gets all machines onboarded to Update Management under this automation account.
    
        .DESCRIPTION
            This function gets all machines onboarded to Automation Update Management under this automation account using log analytics workspace.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
    
        .EXAMPLE
            Populate-AllMachinesOnboardedToUpdateManagement -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )

    try 
    {
        $linkedWorkspace = Invoke-ArmApi-WithPath -Path ($LinkedWorkspacePath -f $AutomationAccountResourceId) -ApiVersion $AutomationApiVersion -Method $GET
        $laResults = Get-MachinesFromLogAnalytics -ResourceId $linkedWorkspace.Response.Id
        if ($laResults.Results.Count -eq 0 -and $null -eq $laResults.Error)
        {
            Write-Telemetry -Message ("Zero machines retrieved from log analytics workspace. If machines were recently onboarded, please wait for few minutes for machines to start reporting to log analytics workspace") -Level $ErrorLvl
            throw
        }
        elseif ($laResults.Results.Count -gt 0 -or @($laResults.Results).Count -gt 0)
        {
            Write-Telemetry -Message ("Retrieved machines from log analytics workspace.")

            foreach ($record in $laResults.Results)
            {
    
                if ($record.ResourceType -eq $ArcVMResourceType -or $record.ResourceType -eq $VMResourceType)
                {
                    [void]$Global:Machines.Add($record.ResourceId)
                }
            }        
        }
        else
        {
            Write-Telemetry -Message ("Failed to get machines from log analytics workspace with error {0}." -f $laResults.Error) -Level $ErrorLvl
            throw
        }          
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled exception {0}." -f, $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Create-UserManagedIdentity
{
    <#
        .SYNOPSIS
            Creates user managed Identity.
    
        .DESCRIPTION
            This function will create user managed Identity in the same subscription and resource group as the automation account.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
    
        .EXAMPLE
            Create-UserManagedIdentity -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )

    try 
    {
        $response = Invoke-ArmApi-WithPath -Path $AutomationAccountResourceId -ApiVersion $AutomationApiVersion -Method $GET
        $Global:AutomationAccountRegion = $response.Response.location
    
        $parts = $AutomationAccountResourceId.Split("/")
        $userManagedIdentityPayload = ConvertFrom-Json $UserManagedIdentityCreationPayload

        $userManagedIdentityPayload.location = $Global:AutomationAccountRegion
        $userManagedIdentityPayload = ConvertTo-Json $userManagedIdentityPayload -Depth $MaxDepth

        $response = Invoke-ArmApi-WithPath -Path ($UserManagedIdentityPath -f $parts[2], $parts[4], $parts[8] + "_AUMMig_uMSI") -ApiVersion $UserManagedIdentityApiVersion -Method $PUT -Payload $userManagedIdentityPayload

        if ($null -eq $response.Response.id)
        {
            Write-Telemetry -Message ("Failed to create user managed identity with error code {0} and error message {1}." -f $response.ErrorCode, $response.ErrorMessage) -Level $ErrorLvl
            throw
        }
        else
        {
            Write-Telemetry -Message ("Successfully created user managed identity with id {0}." -f, $response.Response.id)
            $Global:UserManagedIdentityResourceId = $response.Response.id
            $Global:UserManagedIdentityPrincipalId = $response.Response.properties.principalId
        }
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Register-EventGridResourceProviderToSubscription
{
    <#
        .SYNOPSIS
            Register subscription with Microsoft.EventGrid Resource Provider.
    
        .DESCRIPTION
            This function will register subscription with Microsoft.EventGrid Resource Provider.
    
        .PARAMETER ResourceId
            Resource id.
    
        .EXAMPLE
            Register-EventGridResourceProviderToSubscription ResourceId "{resId}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )

    try 
    {    
        # Register the subscription to which automation account belongs to Microsoft.EventGrid.
        $parts = $ResourceId.Split("/")
        $response = Invoke-ArmApi-WithPath -Path ($EventGridResourceProviderRegistrationPath -f $parts[2]) -ApiVersion $RegisterResourceProviderApiVersion -Method $POST
        if ($null -eq $response.Response.id)
        {
            Write-Telemetry -Message ("Failed to register resource provider Microsoft.EventGrid with subscription {0} with error code {1} and error message {2}." -f $parts[2], $response.ErrorCode, $response.ErrorMessage) -Level $ErrorLvl
        }
        else 
        {
            Write-Telemetry -Message ("Successfully registered resource provider Microsoft.EventGrid with subscription {0}." -f $parts[2])
        }
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled Exception {0} while registering subscription {1} to Microsoft.EventGrid." -f $_.Exception.Message, $parts[2]) -Level $ErrorLvl
        throw
    }
}

function Register-MaitenanceResourceProviderToSubscription
{
    <#
        .SYNOPSIS
            Register subscription with Microsoft.Maintenance Resource Provider.
    
        .DESCRIPTION
            This function will register subscription with Microsoft.Maintenance Resource Provider.
    
        .PARAMETER ResourceId
            Resource id.
    
        .EXAMPLE
            Register-MaitenanceResourceProviderToSubscription ResourceId "{resId}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )

    try 
    {    
        # Register the subscription to which resource belongs to Microsoft.Maintenance.
        $parts = $ResourceId.Split("/")
        if (!$Global:SubscriptionsToRegisterToMaintenanceResourceProvider.ContainsKey($parts[2]))
        {
            $response = Invoke-ArmApi-WithPath -Path ($MaintenanceResourceProviderRegistrationPath -f $parts[2]) -ApiVersion $RegisterResourceProviderApiVersion -Method $POST

            if ($null -eq $response.Response.id)
            {
                Write-Telemetry -Message ("Failed to register resource provider Microsoft.Maintenance with subscription {0} with error code {1} and error message {2}." -f $parts[2], $response.ErrorCode, $response.ErrorMessage) -Level $ErrorLvl
            }
            else 
            {
                Write-Telemetry -Message ("Successfully registered resource provider Microsoft.Maintenance with subscription {0}." -f $parts[2])
                $Global:SubscriptionsToRegisterToMaintenanceResourceProvider[$parts[2]] = $true
            }
        }
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled Exception {0} while registering subscription {1} to Microsoft.Maintenance." -f $_.Exception.Message, $parts[2]) -Level $ErrorLvl
        throw
    }
}

function Add-UserManagedIdentityToAutomationAccount
{
    <#
        .SYNOPSIS
            Adds user managed Identity to the automation account.
    
        .DESCRIPTION
            This function will add user managed Identity to the automation account.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
    
        .EXAMPLE
            Add-UserManagedIdentityToAutomationAccount -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )

    try
    {
        
        $response = Invoke-ArmApi-WithPath -Path $AutomationAccountResourceId -ApiVersion $AutomationApiVersion -Method $GET
        $userManagedIdentityPayload = ConvertFrom-Json $AssignUserManagedIdentityToAutomationAccountPayload

        # Honour the current identity settings for the automation account.
        if ($response.Response.identity.type -Match "userassigned")
        {
            $userManagedIdentityPayload.identity.type = $response.Response.identity.type
        }
        elseif ($response.Response.identity.type -Match "systemassigned")
        {
            $userManagedIdentityPayload.identity.type = "systemassigned,userassigned"
        }
        else
        {
            $userManagedIdentityPayload.identity.type = "userassigned"
        }
        
        # Existing user managed identities should be kept as it is.
        $userManagedIdentities = @{}
        foreach ($property in $response.Response.identity.userAssignedIdentities.psobject.properties)
        {
            [void]$userManagedIdentities.Add($property.Name, @{})
        }
        
        # Add the user managed identity for migration.
        if (!$userManagedIdentities.ContainsKey($Global:UserManagedIdentityResourceId))
        {
            [void]$userManagedIdentities.Add($Global:UserManagedIdentityResourceId, @{})
        }

        $userManagedIdentityPayload.identity.userAssignedIdentities = $userManagedIdentities
        $userManagedIdentityPayload = ConvertTo-Json $userManagedIdentityPayload -Depth $MaxDepth
        
        $response = Invoke-ArmApi-WithPath -Path $AutomationAccountResourceId -ApiVersion $AutomationApiVersion -Method $PATCH -Payload $userManagedIdentityPayload
        if ($response.Status -eq $Failed)
        {
            Write-Telemetry -Message ("Failed to add user managed identity with error code {0} and error message {1}." -f $response.ErrorCode, $response.ErrorMessage) -Level $ErrorLvl
            throw
        }
        else
        {
            Write-Telemetry -Message ("Successfully added user managed identity {0} to automation account {1}." -f, $Global:UserManagedIdentityResourceId, $Global:AutomationAccountRegion)
        }
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Update-AzModules
{
    <#
        .SYNOPSIS
            Updates Az Modules for the automation account.
    
        .DESCRIPTION
            This function will update Az modules for the automation account. Ensure to update any runbooks in the automation account that are not compatible post this update.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
    
        .EXAMPLE
            Update-AzModules -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
    try 
    {
        $response = Invoke-ArmApi-WithPath -Path $AutomationAccountResourceId -ApiVersion $AutomationApiVersion -Method $PATCH -Payload $UpdateAzModulesPayload
        if ($response.Status -eq $Failed)
        {
            Write-Telemetry -Message ("Failed to update Az modules with error code {0} and error message {1}." -f $response.ErrorCode, $response.ErrorMessage) -Level $ErrorLvl
        }
        else
        {
            Write-Telemetry -Message ("Successfully updated Az modules." -f, $Global:UserManagedIdentityResourceId, $Global:AutomationAccountRegion)
        }
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Add-AutomationAccountAzureEnvironmentVariable
{
    <#
        .SYNOPSIS
            Adds azure environment variable for the automation account.
    
        .DESCRIPTION
            This function will add azure environment variable for the automation account.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.

        .PARAMETER AutomationAccountAzureEnvironment
            Azure Cloud to which automation account belongs to.
            
        .EXAMPLE
            Add-AutomationAccountAzureEnvironmentVariable -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}" -AutomationAccountAzureEnvironment "AzureCloud"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$AutomationAccountAzureEnvironment
    )
    try 
    {
        $payload = ConvertFrom-Json $AutomationVariablePayload
        $payload.name = "AutomationAccountAzureEnvironment"
        $payload.properties.value = """$AutomationAccountAzureEnvironment"""
        $payload = ConvertTo-Json $payload -Depth $MaxDepth
        $response = Invoke-ArmApi-WithPath -Path ($AutomationVariablePath -f $AutomationAccountResourceId) -ApiVersion $AutomationVariableApiVersion -Method $PUT -Payload $payload
        if ($null -eq $response.Response.Id -and $response.Status -eq $Failed)
        {
            Write-Telemetry -Message ("Failed to add variable with error code {0} and error message {1}." -f $response.ErrorCode, $response.ErrorMessage) -Level $ErrorLvl
        }
        else
        {
            Write-Telemetry -Message ("Successfully added variable AutomationAccountAzureEnvironment to automation account.")
        }
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}


function Assign-Roles
{
   <#
        .SYNOPSIS
            Assigns role Assignment for the scope specified.
    
        .DESCRIPTION
            This command will assign role Assignment for the scope specifie.

        .PARAMETER RoleDefinitionId
            Role Definition Id.
        
        .PARAMETER Scope
            Role Definition Id.

        .EXAMPLE
            Assign-Roles -RoleDefinitionId RoleDefinitionId -Scope Scope
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$RoleDefinitionId,

        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Scope
    )

    try 
    {
        $payload = ConvertFrom-Json $RoleAssignmentPayload
        $newRoleAssignmentGuid = (New-Guid).Guid.ToString()
        $payload.Id = $newRoleAssignmentGuid
        $payload.Properties.PrincipalId = $Global:UserManagedIdentityPrincipalId
        $payload.Properties.RoleDefinitionId = ($AzureRoleDefinitionPath -f $RoleDefinitionId)
        $payload.Properties.Scope = $Scope
    
        $payload = ConvertTo-Json $payload -Depth $MaxDepth
    
        $response = Invoke-ArmApi-WithPath -Path ($AzureRoleAssignmentPath -f $Scope, $newRoleAssignmentGuid) -ApiVersion $AzureRoleAssignmentApiVersion -Method $PUT -Payload $payload

        if ($null -eq $response.Response.Id)
        {
            Write-Telemetry -Message ("Failed to assign role {0} to scope {1}." -f, $RoleDefinitionId, $Scope)                        
        }
        else
        {
            Write-Telemetry -Message ("Successfully assigned role {0} to scope {1}." -f, $RoleDefinitionId, $Scope)
        }
    }
    catch [Exception]
    {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Get-AllSoftwareUpdateConfigurations
{
    <#
        .SYNOPSIS
            Gets all software update configurations.
    
        .DESCRIPTION
            This function gets all software update configurations with support for pagination.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
            
        .EXAMPLE
            Get-AllSoftwareUpdateConfigurations -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
    $output = $null
    $skip = 0
    do
    {
        $path = ($SoftwareUpdateConfigurationsPath -f $AutomationAccountResourceId, $skip)
        $output = Invoke-ArmApi-WithPath -Path $path -ApiVersion $SoftwareUpdateConfigurationApiVersion -Method $GET
        if($output.Status -eq $Failed)
        {
            Write-Telemetry -Message ("Failed to get software update configurations with error code {0} and error message {1}." -f $output.ErrorCode, $output.ErrorMessage)
            throw
        }
        foreach ($result in $output.Response.value)
        {
            if (!$Global:SoftwareUpdateConfigurationsResourceIDs.ContainsKey($result.id))
            {
                $Global:SoftwareUpdateConfigurationsResourceIDs[$result.id] = $result.name
            }
        }
        # API paginates in multiples of 100.
        $skip = $skip + 100
    }
    while ($null -ne $output.Response.nextLink);
}

function Add-RoleAssignmentsForAzureDynamicMachinesScope
{
   <#
        .SYNOPSIS
            Adds required roles assignments for azure dynamic machines scope.
    
        .DESCRIPTION
            This command will add required roles assignments for azure dynamic machines scope.

        .PARAMETER AutomationAccountResourceId
            Automation Account Resource Id.

        .EXAMPLE
            Add-RoleAssignmentsForAzureDynamicMachinesScope -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
    Get-AllSoftwareUpdateConfigurations -AutomationAccountResourceId $AutomationAccountResourceId
     
    $softwareUpdateConfigurations = [System.Collections.ArrayList]@($Global:SoftwareUpdateConfigurationsResourceIDs.Keys)

    foreach ($softwareUpdateConfiguration in $softwareUpdateConfigurations)
    {
        try 
        {
            $softwareUpdateConfigurationData = Invoke-ArmApi-WithPath -Path $softwareUpdateConfiguration -ApiVersion $SoftwareUpdateConfigurationApiVersion -Method $GET
            if ($softwareUpdateConfigurationData.Status -eq $Failed)
            {
                Write-Telemetry -Message ("Failed to get software update configuration {0} with error code {1} and error message {2}." -f $softwareUpdateConfiguration, $softwareUpdateConfigurationData.ErrorCode, $softwareUpdateConfigurationData.ErrorMessage) -Level $ErrorLvl
            }
            elseif ($null -ne $softwareUpdateConfigurationData.Response.properties.updateConfiguration.targets.azureQueries)
            {
                foreach ($azureQuery in $softwareUpdateConfigurationData.Response.properties.updateConfiguration.targets.azureQueries)
                {
                    foreach ($scope in $azureQuery.scope)
                    {
                        try
                        {
                            if (!$Global:AzureDynamicQueriesScope.ContainsKey($scope))
                            {
                                $scopeAtSubscriptionLevel = $scope.Split("/")
                                
                                # Register subscription in query with Microsoft.Maintenance Resource Provider.
                                Register-MaitenanceResourceProviderToSubscription -ResourceId $scope

                                # Virtual machine contributor access for the scope to run arg queries and set patch properties and config assignments
                                Assign-Roles -RoleDefinitionId $VirtualMachineContributorRole -Scope $scope
    
                                # Scheduled patching contributor role for configuration assignments at the subscription level.
                                Assign-Roles -RoleDefinitionId $ScheduledPatchingContributorRole -Scope ("/subscriptions/" + $scopeAtSubscriptionLevel[2])
                                
                                # Save in dictionary to avoid reassigning roles for the same scope again.
                                $Global:AzureDynamicQueriesScope[$scope] = $true
                            }
                        }
                        catch [Exception]
                        {
                            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
                        }
                    }
                }
            }
        }
        catch [Exception]
        {
            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        }
    }
}

function Add-RoleAssignmentsForMachines
{
   <#
        .SYNOPSIS
            Adds required roles assignments for automation account.
    
        .DESCRIPTION
            This command will add required roles assignments for automation account.

        .EXAMPLE
            Add-RoleAssignmentsForMachines
    #>
    foreach($machine in $Global:Machines)
    {
        try 
        {
            # Register subscription to which machine belongs with Microsoft.Maintenance Resource Provider.
            Register-MaitenanceResourceProviderToSubscription -ResourceId $machine

            if ($machine -Match "microsoft.hybridcompute")
            {
                # Arc machine contributor access for arc machines.
                Assign-Roles -RoleDefinitionId $AzureConnectedMachineOnboardingRole -Scope $machine
            }
            else
            {
                # Virtual machine contributor access for azure machines.
                Assign-Roles -RoleDefinitionId $VirtualMachineContributorRole -Scope $machine
            }

            # Scheduled patching contributor role for configuration assignments.
            Assign-Roles -RoleDefinitionId $ScheduledPatchingContributorRole -Scope $machine
        }
        catch [Exception]
        {
            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        }
    }
}

function Add-RoleAssignmentsForAutomationAccount
{
   <#
        .SYNOPSIS
            Adds required roles assignments for automation account.
    
        .DESCRIPTION
            This command will add required roles assignments for automation account.

        .PARAMETER AutomationAccountResourceId
            Automation Account Resource Id.

        .EXAMPLE
            Add-RoleAssignmentsForAutomationAccount -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )

    $parts = $AutomationAccountResourceId.Split("/")

    # Register subscription to which automation account belongs with Microsoft.Maintenance Resource Provider.
    Register-MaitenanceResourceProviderToSubscription -ResourceId $AutomationAccountResourceId

    # Virtual machine contributor access to the resource group to which automation account belongs.
    Assign-Roles -RoleDefinitionId $VirtualMachineContributorRole -Scope ("/subscriptions/{0}/resourceGroups/{1}" -f $parts[2], $parts[4])

    # Contributor access to the subscription to which automation account belongs. This is required for creating new resource group in that subscription for maintenance configurations.
    Assign-Roles -RoleDefinitionId $ContributorRole -Scope ("/subscriptions/{0}/" -f $parts[2])

    # Automation operator so that schedules can be disabled post migration.
    Assign-Roles -RoleDefinitionId $AutomationOperatorRole -Scope $AutomationAccountResourceId

    # Scheduled patching contributor access to the subscription to which automation account belongs. A new resource group will be created in this subscription in the same location as the automation account for maintenance configurations.
    Assign-Roles -RoleDefinitionId $ScheduledPatchingContributorRole -Scope ("/subscriptions/{0}" -f $parts[2])
}

function Add-RoleAssignmentsForLogAnalyticsWorkspaceAndSolution
{
   <#
        .SYNOPSIS
            Adds required roles assignments for log analytics workspace and solution.
    
        .DESCRIPTION
            This command will add required roles assignments for log analytics workspace and solution.

        .PARAMETER AutomationAccountResourceId
            Automation Account Resource Id.

        .EXAMPLE
            Add-RoleAssignmentsForLogAnalyticsWorkspaceAndSolution -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )

    $response = Invoke-ArmApi-WithPath -Path ($LinkedWorkspacePath -f $AutomationAccountResourceId) -ApiVersion $AutomationApiVersion -Method $GET

    if ($response.Status-eq $Failed)
    {
        Write-Telemetry -Message ("Failed to get linked log analytics workspace for {0}." -f $AutomationAccountResourceId) -Level $ErrorLvl
        throw
    }
    
    $linkedWorkspace = $response.Response.Id
    # Contributor access on the log analytics workspace.
    Assign-Roles -RoleDefinitionId $LogAnalyticsContributorRole -Scope $linkedWorkspace

    $parts = $linkedWorkspace.Split("/")
    # Reader access on the subscription to which the log analytics workspace belongs.
    Assign-Roles -RoleDefinitionId $LogAnalyticsReaderRole -Scope ("/subscriptions/" + $parts[2])

    $response = Invoke-ArmApi-WithPath -Path ($SolutionsWithWorkspaceFilterPath -f $parts[2], $parts[4], $parts[8]) -ApiVersion $SolutionsApiVersion -Method $GET
    
    if ($response.Status -eq $Failed)
    {
        Write-Telemetry -Message ("Failed to get solutions for log analytics workspace {0}." -f $linkedWorkspace) -Level $ErrorLvl
        throw
    }
    
    foreach ($solution in $response.Response.value)
    {
        $name = ("Updates(" + $parts[8] + ")")
        if ($solution.name -eq $name )
        {
            # Contributor access on the log analytics workspace updates solution.
            Assign-Roles -RoleDefinitionId $LogAnalyticsContributorRole -Scope $solution.id
        }
    }
}

$azConnect = Connect-AzAccount -UseDeviceAuthentication -SubscriptionId $AutomationAccountResourceId.Split("/")[2] -Environment $AutomationAccountAzureEnvironment
if ($null -eq $azConnect)
{
    Write-Telemetry -Message ("Failed to connect to azure.") -Level $ErrorLvl
    throw
}
else
{
    Write-Telemetry -Message ("Successfully connected with account {0} to subscription {1}" -f $azConnect.Context.Account, $azConnect.Context.Subscription)
}

try
{
    Populate-AllMachinesOnboardedToUpdateManagement -AutomationAccountResourceId $AutomationAccountResourceId
    Update-AzModules -AutomationAccountResourceId $AutomationAccountResourceId
    Add-AutomationAccountAzureEnvironmentVariable -AutomationAccountResourceId $AutomationAccountResourceId -AutomationAccountAzureEnvironment $AutomationAccountAzureEnvironment
    Create-UserManagedIdentity -AutomationAccountResourceId $AutomationAccountResourceId
    Add-UserManagedIdentityToAutomationAccount -AutomationAccountResourceId $AutomationAccountResourceId
    Add-RoleAssignmentsForAutomationAccount -AutomationAccountResourceId $AutomationAccountResourceId
    Add-RoleAssignmentsForLogAnalyticsWorkspaceAndSolution -AutomationAccountResourceId $AutomationAccountResourceId
    Add-RoleAssignmentsForMachines
    Add-RoleAssignmentsForAzureDynamicMachinesScope -AutomationAccountResourceId $AutomationAccountResourceId
    Register-EventGridResourceProviderToSubscription -ResourceId $AutomationAccountResourceId

    Write-Output ("User Managed identity {0} successfully created, linked and assigned required roles for migration of automation account {1}." -f $Global:UserManagedIdentityResourceId, $AutomationAccountResourceId)
}
catch [Exception]
{
    Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
}

Below is an advanced set of standalone PowerShell scripts that not only cover common Azure use cases (VM management, Azure AD reporting, AKS health, Web Apps, Azure Functions, Graph API security, and OS monitoring) but also include two additional genuine DevOps use cases for Azure Cloud. These additional use cases are:

- **Use Case 10: Azure Resource Graph Inventory & Policy Compliance Reporting**  
  This script uses Azure Resource Graph to query your entire subscription, flagging resources that do not have a required tag (for example, “Environment”). This is critical for enforcing policies and cost allocation.

- **Use Case 11: Azure Container Registry (ACR) Unused Images Cleanup**  
  This script queries an Azure Container Registry for images older than a specified threshold (in days) and, with confirmation, deletes them to free up space and reduce clutter.

Each script is now a fully parameterized, production‐grade script that uses advanced PowerShell concepts such as parameter validation, CmdletBinding with SupportsShouldProcess, robust error handling with try/catch, verbose logging, PSCustomObject creation, file operations (CSV export), and secure secret retrieval from Key Vault (when needed). You can dot‑source or import a common configuration module (shown below) to share global settings.

Below, each script is preceded by a bullet-point summary header. Finally, a master “Run_All_Reports.ps1” script is provided to call every individual script sequentially and generate a consolidated set of reports.

---

### • Global Configuration & Common Setup (CommonConfig.psm1)

Save the following to a file named **CommonConfig.psm1**. This module defines two common functions: one to initialize global configuration from environment variables (with overrideable parameters) and another to obtain a Microsoft Graph API token.

```powershell
# CommonConfig.psm1

function Initialize-GlobalConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TenantId = $env:AZURE_TENANT_ID,
        [Parameter(Mandatory = $false)]
        [string]$ClientId = $env:AZURE_CLIENT_ID,
        [Parameter(Mandatory = $false)]
        [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroup = $env:RESOURCE_GROUP,
        [Parameter(Mandatory = $false)]
        [string]$StorageAccount = $env:STORAGE_ACCOUNT,
        [Parameter(Mandatory = $false)]
        [string]$KeyVaultName = $env:KEY_VAULT
    )

    $global:TenantId       = $TenantId
    $global:ClientId       = $ClientId
    $global:ClientSecret   = $ClientSecret
    $global:ResourceGroup  = $ResourceGroup
    $global:StorageAccount = $StorageAccount
    $global:KeyVaultName   = $KeyVaultName

    try {
        Write-Verbose "Attempting to login to Azure..."
        Connect-AzAccount -ErrorAction Stop
        Write-Verbose "Azure login succeeded."
    }
    catch {
        Write-Error "Azure login failed: $_"
        exit 1
    }
}

function Get-GraphToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [string]$ClientId,
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )

    $Body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    try {
        Write-Verbose "Requesting Graph API access token..."
        $TokenResponse = Invoke-RestMethod -Method Post `
                          -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                          -Body $Body -ContentType "application/x-www-form-urlencoded"
        Write-Verbose "Graph API token acquired."
        return $TokenResponse.access_token
    }
    catch {
        Write-Error "Error obtaining Graph token: $_"
        exit 1
    }
}

Export-ModuleMember -Function *
```

You can load this module at the top of each script with:

```powershell
. .\CommonConfig.psm1
Initialize-GlobalConfig  # uses environment variables by default (override via parameters if needed)
```

---

### • Script 1: Advanced Virtual Machine Management  
*Retrieves all Azure VMs, creates a performance report (CSV), and automatically restarts any VM detected as “stopped”.*  
Save as **VM_Management.ps1**.

```powershell
<#
.SYNOPSIS
    Advanced VM Management script.
.DESCRIPTION
    Retrieves all VMs, logs power states, and auto-restarts VMs if stopped.
.PARAMETER ResourceGroup
    The resource group name. Defaults from environment/global configuration.
.EXAMPLE
    .\VM_Management.ps1 -ResourceGroup "MyResourceGroup"
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = $env:RESOURCE_GROUP
)

. .\CommonConfig.psm1
Initialize-GlobalConfig -ResourceGroup $ResourceGroup

Write-Output "Collecting VM status and performance data..."
try {
    $vms = Get-AzVM -ErrorAction Stop
}
catch {
    Write-Error "Error retrieving VMs: $_"
    exit 1
}

$vmReport = @()
foreach ($vm in $vms) {
    $rg     = $vm.ResourceGroupName
    $vmName = $vm.Name
    try {
        $vmInstance = Get-AzVM -ResourceGroupName $rg -Name $vmName -Status -ErrorAction Stop
        $powerState = ($vmInstance.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
    }
    catch {
        Write-Warning "Unable to retrieve status for VM '$vmName': $_"
        continue
    }
    $reportItem = [PSCustomObject]@{
        VMName        = $vmName
        ResourceGroup = $rg
        PowerState    = $powerState
        ReportTime    = (Get-Date)
    }
    $vmReport += $reportItem

    if ($powerState -match "stopped") {
        if ($PSCmdlet.ShouldProcess("VM $vmName", "Restart VM")) {
            Write-Output "VM '$vmName' is stopped. Initiating restart..."
            Restart-AzVM -ResourceGroupName $rg -Name $vmName -Force -ErrorAction SilentlyContinue
        }
    }
}

$vmReport | Export-Csv -Path "VM_Performance_Report.csv" -NoTypeInformation
Write-Output "VM performance report saved as 'VM_Performance_Report.csv'."
```

---

### • Script 2: Advanced Azure AD Reporting via Microsoft Graph API  
*Retrieves Azure AD users and, for each, lists group memberships (filtered for “Admin” groups) and exports the report (CSV).*  
Save as **AAD_Report.ps1**.

```powershell
<#
.SYNOPSIS
    Azure AD Reporting via Graph API.
.DESCRIPTION
    Retrieves AD users and filters group memberships for names containing "Admin".
.PARAMETER TenantId
    Azure tenant ID; defaults from environment/global configuration.
.EXAMPLE
    .\AAD_Report.ps1
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID
)

. .\CommonConfig.psm1
Initialize-GlobalConfig -TenantId $TenantId

Write-Output "Requesting Microsoft Graph API token..."
$graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

Write-Output "Fetching Azure AD users via Graph API..."
$usersUri = "https://graph.microsoft.com/v1.0/users"
try {
    $usersResponse = Invoke-RestMethod -Method Get -Uri $usersUri -Headers @{ Authorization = "Bearer $graphToken" } -ErrorAction Stop
}
catch {
    Write-Error "Error fetching AD users: $_"
    exit 1
}

$report = @()
foreach ($user in $usersResponse.value) {
    $groupsUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
    try {
        $groupsResponse = Invoke-RestMethod -Method Get -Uri $groupsUri -Headers @{ Authorization = "Bearer $graphToken" }
        $adminGroups = $groupsResponse.value | Where-Object { $_.displayName -match "Admin" } | ForEach-Object { $_.displayName }
    }
    catch {
        $adminGroups = "Error retrieving groups"
    }
    $reportItem = [PSCustomObject]@{
        UserPrincipalName = $user.userPrincipalName
        DisplayName       = $user.displayName
        AdminGroups       = ($adminGroups -join ", ")
        ReportTime        = (Get-Date)
    }
    $report += $reportItem
}

$report | Export-Csv -Path "AzureAD_Users_Groups_Report.csv" -NoTypeInformation
Write-Output "Azure AD report saved as 'AzureAD_Users_Groups_Report.csv'."
```

---

### • Script 3: AKS Cluster Health & Scaling  
*Retrieves AKS clusters, uses Azure CLI & kubectl to obtain node status, and exports a report (CSV).*  
Save as **AKS_Health.ps1**.

```powershell
<#
.SYNOPSIS
    AKS Cluster Health Reporting.
.DESCRIPTION
    Retrieves AKS cluster details and node states; exports a CSV report.
.PARAMETER ResourceGroup
    The resource group containing AKS clusters.
.EXAMPLE
    .\AKS_Health.ps1 -ResourceGroup "MyResourceGroup"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = $env:RESOURCE_GROUP
)

. .\CommonConfig.psm1
Initialize-GlobalConfig -ResourceGroup $ResourceGroup

Write-Output "Collecting AKS cluster health information..."
try {
    $aksClusters = Get-AzAks -ResourceGroupName $ResourceGroup -ErrorAction Stop
}
catch {
    Write-Error "Error retrieving AKS clusters: $_"
    exit 1
}

$aksReport = @()
foreach ($aks in $aksClusters) {
    $rg = $aks.ResourceGroupName
    $clusterName = $aks.Name
    Write-Output "Fetching credentials for AKS cluster '$clusterName'..."
    try {
        az aks get-credentials --resource-group $rg --name $clusterName --overwrite-existing | Out-Null
    }
    catch {
        Write-Warning "Failed to get credentials for '$clusterName': $_"
        continue
    }
    try {
        $nodesJson = kubectl get nodes -o json 2>$null
        $nodes = $nodesJson | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not retrieve nodes for '$clusterName': $_"
        continue
    }
    $nodeCount = $nodes.items.Count
    $unhealthyNodes = ($nodes.items | Where-Object {
        $_.status.conditions | Where-Object { $_.type -eq "Ready" -and $_.status -ne "True" }
    }).Count

    $reportItem = [PSCustomObject]@{
        ClusterName    = $clusterName
        ResourceGroup  = $rg
        TotalNodes     = $nodeCount
        UnhealthyNodes = $unhealthyNodes
        ReportTime     = (Get-Date)
    }
    $aksReport += $reportItem
}

$aksReport | Export-Csv -Path "AKS_Health_Report.csv" -NoTypeInformation
Write-Output "AKS health report saved as 'AKS_Health_Report.csv'."
```

---

### • Script 4: Web App Performance & Deployment Automation  
*Retrieves Web Apps to generate a status report and updates a target Web App’s configuration with a Key Vault secret.*  
Save as **WebApp_Status.ps1**.

```powershell
<#
.SYNOPSIS
    Web App Status and Configuration Update.
.DESCRIPTION
    Retrieves Web Apps, creates a status report, and updates configuration of a specified Web App with a secret from Key Vault.
.PARAMETER ResourceGroup
    The resource group of the Web Apps.
.PARAMETER TargetWebApp
    The specific Web App to update.
.PARAMETER SecretName
    The name of the Key Vault secret to use.
.EXAMPLE
    .\WebApp_Status.ps1 -ResourceGroup "MyRG" -TargetWebApp "MyApp" -SecretName "AppConfigSecret"
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = $env:RESOURCE_GROUP,
    [Parameter(Mandatory = $true)]
    [string]$TargetWebApp,
    [Parameter(Mandatory = $true)]
    [string]$SecretName
)

. .\CommonConfig.psm1
Initialize-GlobalConfig -ResourceGroup $ResourceGroup

Write-Output "Retrieving Azure Web App status..."
try {
    $webApps = Get-AzWebApp -ResourceGroupName $ResourceGroup -ErrorAction Stop
}
catch {
    Write-Error "Error retrieving Web Apps: $_"
    exit 1
}

$report = @()
foreach ($app in $webApps) {
    $reportItem = [PSCustomObject]@{
        WebAppName    = $app.Name
        ResourceGroup = $app.ResourceGroup
        State         = $app.State
        Hostname      = $app.DefaultHostName
        ReportTime    = (Get-Date)
    }
    $report += $reportItem
}
$report | Export-Csv -Path "WebApp_Status_Report.csv" -NoTypeInformation
Write-Output "Web App report saved as 'WebApp_Status_Report.csv'."

# Update configuration with secret from Key Vault.
try {
    Write-Output "Retrieving secret '$SecretName' from Key Vault..."
    $secretValue = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -ErrorAction Stop).SecretValueText
    if ($PSCmdlet.ShouldProcess("WebApp $TargetWebApp", "Update AppSettings with secret")) {
        Set-AzWebApp -ResourceGroupName $ResourceGroup -Name $TargetWebApp -AppSettings @{ "ConfigSecret" = $secretValue }
        Write-Output "Updated Web App '$TargetWebApp' configuration with Key Vault secret."
    }
}
catch {
    Write-Warning "Web App configuration update failed: $_"
}
```

---

### • Script 5: Azure Functions Health & Reporting  
*Retrieves Azure Function Apps, compiles a status report, and exports to CSV.*  
Save as **AzureFunctions_Status.ps1**.

```powershell
<#
.SYNOPSIS
    Azure Functions Health Reporting.
.DESCRIPTION
    Retrieves the status of all Azure Function Apps and exports a report (CSV).
.PARAMETER ResourceGroup
    The resource group containing Azure Functions.
.EXAMPLE
    .\AzureFunctions_Status.ps1 -ResourceGroup "MyResourceGroup"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = $env:RESOURCE_GROUP
)

. .\CommonConfig.psm1
Initialize-GlobalConfig -ResourceGroup $ResourceGroup

Write-Output "Collecting Azure Functions status..."
try {
    $functionApps = Get-AzFunctionApp -ResourceGroupName $ResourceGroup -ErrorAction Stop
}
catch {
    Write-Error "Error retrieving Azure Functions: $_"
    exit 1
}

$report = @()
foreach ($func in $functionApps) {
    $reportItem = [PSCustomObject]@{
        FunctionAppName = $func.Name
        ResourceGroup   = $func.ResourceGroup
        State           = $func.State
        DefaultHostName = $func.DefaultHostName
        ReportTime      = (Get-Date)
    }
    $report += $reportItem
}

$report | Export-Csv -Path "AzureFunctions_Status_Report.csv" -NoTypeInformation
Write-Output "Azure Functions report saved as 'AzureFunctions_Status_Report.csv'."
```

---

### • Script 6: Graph API Security Alerts Aggregator  
*Uses Microsoft Graph API to fetch security alerts and exports them as a CSV report.*  
Save as **Graph_SecurityAlerts.ps1**.

```powershell
<#
.SYNOPSIS
    Graph API Security Alerts Aggregator.
.DESCRIPTION
    Retrieves security alerts from Microsoft Graph API and exports them.
.PARAMETER TenantId
    Azure Tenant ID; defaults from global configuration.
.EXAMPLE
    .\Graph_SecurityAlerts.ps1
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID
)

. .\CommonConfig.psm1
Initialize-GlobalConfig -TenantId $TenantId

Write-Output "Obtaining Microsoft Graph API token..."
$body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
try {
    $tokenResponse = Invoke-RestMethod -Method Post `
                     -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                     -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    $graphToken = $tokenResponse.access_token
}
catch {
    Write-Error "Error obtaining Graph token: $_"
    exit 1
}

Write-Output "Fetching security alerts from Microsoft Graph API..."
$alertsUri = "https://graph.microsoft.com/v1.0/security/alerts"
try {
    $alertsResponse = Invoke-RestMethod -Method Get -Uri $alertsUri -Headers @{ Authorization = "Bearer $graphToken" } -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve security alerts: $_"
    exit 1
}

$report = $alertsResponse.value | ForEach-Object {
    [PSCustomObject]@{
        AlertId          = $_.id
        Title            = $_.title
        Category         = $_.category
        Severity         = $_.severity
        Status           = $_.status
        DetectedDateTime = $_.detectedDateTime
    }
}

$report | Export-Csv -Path "Graph_Security_Alerts_Report.csv" -NoTypeInformation
Write-Output "Security alerts report saved as 'Graph_Security_Alerts_Report.csv'."
```

---

### • Script 7: OS-Level Monitoring & Reporting  
*Collects local system metrics (CPU, disk, memory) using counters and CIM queries, then exports a CSV report.*  
Save as **OS_Performance.ps1**.

```powershell
<#
.SYNOPSIS
    Local OS Performance Monitoring.
.DESCRIPTION
    Uses performance counters and CIM queries to report on CPU usage, disk space, and memory.
.EXAMPLE
    .\OS_Performance.ps1
#>
[CmdletBinding()]
param ()

. .\CommonConfig.psm1
Initialize-GlobalConfig

Write-Output "Retrieving local system performance metrics..."
$cpu = Get-Counter '\Processor(_Total)\% Processor Time'
$cpuUsage = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object FreeSpace, Size
$freeDiskGB  = [math]::Round($disk.FreeSpace / 1GB, 2)
$totalDiskGB = [math]::Round($disk.Size / 1GB, 2)
$mem = Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory, TotalVisibleMemorySize
$freeMemMB  = [math]::Round($mem.FreePhysicalMemory / 1024, 2)
$totalMemMB = [math]::Round($mem.TotalVisibleMemorySize / 1024, 2)

$report = [PSCustomObject]@{
    Timestamp      = (Get-Date)
    CPU_Usage      = "$cpuUsage%"
    FreeDisk_GB    = $freeDiskGB
    TotalDisk_GB   = $totalDiskGB
    FreeMemory_MB  = $freeMemMB
    TotalMemory_MB = $totalMemMB
}

$report | Export-Csv -Path "OS_Performance_Report.csv" -NoTypeInformation
Write-Output "OS performance report saved as 'OS_Performance_Report.csv'."
```

---

### • Script 8: Azure Resource Graph Inventory & Policy Compliance Reporting  
*This new script queries the Azure Resource Graph to list all resources that are missing a required tag (e.g., “Environment”) and exports a CSV report.*  
Save as **ResourceGraph_Compliance.ps1**.

```powershell
<#
.SYNOPSIS
    Azure Resource Inventory & Compliance Reporting.
.DESCRIPTION
    Queries all resources in the subscription via Azure Resource Graph and flags those missing a required tag.
.PARAMETER RequiredTag
    The name of the required tag (default: "Environment").
.EXAMPLE
    .\ResourceGraph_Compliance.ps1 -RequiredTag "Environment"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$RequiredTag = "Environment"
)

. .\CommonConfig.psm1
Initialize-GlobalConfig

Write-Output "Querying Azure Resource Graph for resources missing the tag '$RequiredTag'..."
# Build the query that finds resources with no tag under the specified required tag name.
$query = @"
Resources
| where isnull(tags['$RequiredTag'])
"@

try {
    $results = Search-AzGraph -Query $query -ErrorAction Stop
}
catch {
    Write-Error "Error querying Azure Resource Graph: $_"
    exit 1
}

$report = $results | ForEach-Object {
    [PSCustomObject]@{
        ResourceId   = $_.id
        ResourceType = $_.type
        Location     = $_.location
        MissingTag   = $RequiredTag
        ReportTime   = (Get-Date)
    }
}

$report | Export-Csv -Path "ResourceGraph_Compliance_Report.csv" -NoTypeInformation
Write-Output "Resource Graph compliance report saved as 'ResourceGraph_Compliance_Report.csv'."
```

---

### • Script 9: Azure Container Registry (ACR) Unused Images Cleanup  
*This new script queries an Azure Container Registry for images older than a specified threshold (in days) and, with confirmation, deletes them to reclaim space.*  
Save as **ACR_ImageCleanup.ps1**.

```powershell
<#
.SYNOPSIS
    ACR Unused Images Cleanup.
.DESCRIPTION
    Lists container images from the given Azure Container Registry older than the specified threshold (in days) and deletes them upon confirmation.
.PARAMETER ACRName
    The name of the Azure Container Registry.
.PARAMETER DaysThreshold
    The age threshold (in days) for selecting images to delete. Default is 30 days.
.EXAMPLE
    .\ACR_ImageCleanup.ps1 -ACRName "myacr" -DaysThreshold 30
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $true)]
    [string]$ACRName,
    [Parameter(Mandatory = $false)]
    [int]$DaysThreshold = 30
)

. .\CommonConfig.psm1
Initialize-GlobalConfig

Write-Output "Listing repositories in ACR '$ACRName'..."
try {
    $reposJson = az acr repository list --name $ACRName --output json
    $repos = $reposJson | ConvertFrom-Json
}
catch {
    Write-Error "Error retrieving repositories from ACR: $_"
    exit 1
}

$cleanupReport = @()
$thresholdDate = (Get-Date).AddDays(-$DaysThreshold)

foreach ($repo in $repos) {
    Write-Output "Processing repository: $repo"
    try {
        # List manifests for the repository (which include the image creation time)
        $manifestsJson = az acr repository show-manifests --name $ACRName --repository $repo --output json
        $manifests = $manifestsJson | ConvertFrom-Json
    }
    catch {
        Write-Warning "Failed to retrieve manifests for repository $repo: $_"
        continue
    }
    
    foreach ($manifest in $manifests) {
        # Assumes the manifest has a property "lastUpdateTime" in ISO8601 format.
        $lastUpdate = Get-Date $manifest.lastUpdateTime
        if ($lastUpdate -lt $thresholdDate) {
            $cleanupItem = [PSCustomObject]@{
                Repository     = $repo
                ManifestDigest = $manifest.digest
                LastUpdateTime = $lastUpdate
                ReportTime     = (Get-Date)
            }
            $cleanupReport += $cleanupItem
            
            if ($PSCmdlet.ShouldProcess("Repo: $repo, Digest: $($manifest.digest)", "Delete image older than $DaysThreshold days")) {
                try {
                    az acr repository delete --name $ACRName --repository $repo --manifest $manifest.digest --yes | Out-Null
                    Write-Output "Deleted image from repository '$repo' with digest '$($manifest.digest)'."
                }
                catch {
                    Write-Warning "Failed to delete image with digest '$($manifest.digest)': $_"
                }
            }
        }
    }
}

$cleanupReport | Export-Csv -Path "ACR_ImageCleanup_Report.csv" -NoTypeInformation
Write-Output "ACR image cleanup report saved as 'ACR_ImageCleanup_Report.csv'."
```

---

### • Final Consolidated Workflow Execution (Optional Master Script)  
*This master script sequentially calls all the individual scripts (from script 1 through 9) to generate a final consolidated report for every use case.*  
Save as **Run_All_Reports.ps1**.

```powershell
<#
.SYNOPSIS
    Consolidated workflow to run all advanced automation scripts.
.DESCRIPTION
    Sequentially executes VM, Azure AD, AKS, Web App, Azure Functions, Graph Security Alerts, OS Performance, Resource Graph compliance, and ACR image cleanup scripts.
.EXAMPLE
    .\Run_All_Reports.ps1
#>
[CmdletBinding()]
param ()

Write-Output "-------- Starting Advanced Azure Cloud Automation Workflow --------"

# Assume the individual scripts (VM_Management.ps1, AAD_Report.ps1, AKS_Health.ps1, WebApp_Status.ps1, AzureFunctions_Status.ps1, Graph_SecurityAlerts.ps1, OS_Performance.ps1, ResourceGraph_Compliance.ps1, ACR_ImageCleanup.ps1) are in the same folder.
. .\VM_Management.ps1
. .\AAD_Report.ps1
. .\AKS_Health.ps1
. .\WebApp_Status.ps1 -TargetWebApp "YourTargetWebApp" -SecretName "AppConfigSecret"
. .\AzureFunctions_Status.ps1
. .\Graph_SecurityAlerts.ps1
. .\OS_Performance.ps1
. .\ResourceGraph_Compliance.ps1 -RequiredTag "Environment"
. .\ACR_ImageCleanup.ps1 -ACRName "myacr" -DaysThreshold 30

Write-Output "-------- All reports generated successfully. --------"
```

---

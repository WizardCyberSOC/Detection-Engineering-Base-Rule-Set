## Globals ##
$CloudEnv = $Env:cloudEnv
$ResourceGroupName = $Env:resourceGroupName
$WorkspaceName = $Env:workspaceName
$WorkspaceId = $Env:workspaceId
$Directory = $Env:directory
$contentTypes = $Env:contentTypes
$ChangedFiles = $Env:CHANGED_FILES
$DeletedFiles = $Env:DELETED_FILES
$contentTypeMapping = @{
    "AnalyticsRule"=@("Microsoft.OperationalInsights/workspaces/providers/alertRules", "Microsoft.OperationalInsights/workspaces/providers/alertRules/actions");
    "AutomationRule"=@("Microsoft.OperationalInsights/workspaces/providers/automationRules");
    "HuntingQuery"=@("Microsoft.OperationalInsights/workspaces/savedSearches");
    "Parser"=@("Microsoft.OperationalInsights/workspaces/savedSearches");
    "Playbook"=@("Microsoft.Web/connections", "Microsoft.Logic/workflows", "Microsoft.Web/customApis");
    "Workbook"=@("Microsoft.Insights/workbooks");
}
$sourceControlId = $Env:sourceControlId
$rootDirectory = $Env:rootDirectory
$githubAuthToken = $Env:githubAuthToken
$githubRepository = $Env:GITHUB_REPOSITORY
$branchName = $Env:branch
$smartDeployment = $Env:smartDeployment
$newResourceBranch = $branchName + "-sentinel-deployment"
$csvPath = "$rootDirectory\.sentinel\tracking_table_$sourceControlId.csv"
$configPath = "$rootDirectory\sentinel-deployment.config"
$global:localCsvTablefinal = @{}
$global:updatedCsvTable = @{}
$global:parameterFileMapping = @{}
$global:prioritizedContentFiles = @()
$global:excludeContentFiles = @()

$guidPattern = '(\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b)'
$namePattern = '([-\w\._\(\)]+)'
$sentinelResourcePatterns = @{
    "AnalyticsRule" = "/subscriptions/$guidPattern/resourceGroups/$namePattern/providers/Microsoft.OperationalInsights/workspaces/$namePattern/providers/Microsoft.SecurityInsights/alertRules/$namePattern"
    "AutomationRule" = "/subscriptions/$guidPattern/resourceGroups/$namePattern/providers/Microsoft.OperationalInsights/workspaces/$namePattern/providers/Microsoft.SecurityInsights/automationRules/$namePattern"
    "HuntingQuery" = "/subscriptions/$guidPattern/resourceGroups/$namePattern/providers/Microsoft.OperationalInsights/workspaces/$namePattern/savedSearches/$namePattern"
    "Parser" = "/subscriptions/$guidPattern/resourceGroups/$namePattern/providers/Microsoft.OperationalInsights/workspaces/$namePattern/savedSearches/$namePattern"
    "Playbook" = "/subscriptions/$guidPattern/resourceGroups/$namePattern/providers/Microsoft.Logic/workflows/$namePattern"
    "Workbook" = "/subscriptions/$guidPattern/resourceGroups/$namePattern/providers/Microsoft.Insights/workbooks/$namePattern"
}

if ([string]::IsNullOrEmpty($contentTypes)) {
    $contentTypes = "AnalyticsRule"
}

$metadataFilePath = "metadata.json"
@"
{
    "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "parentResourceId": {
            "type": "string"
        },
        "kind": {
            "type": "string"
        },
        "sourceControlId": {
            "type": "string"
        },
        "workspace": {
            "type": "string"
        },
        "contentId": {
            "type": "string"
        },
        "customVersion": {
            "type": "string"
        }
    },
    "variables": {
        "metadataName": "[concat(toLower(parameters('kind')), '-', parameters('contentId'))]"
    },
    "resources": [
        {
            "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
            "apiVersion": "2022-01-01-preview",
            "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',variables('metadataName'))]",
            "properties": {
                "parentId": "[parameters('parentResourceId')]",
                "kind": "[parameters('kind')]",
                "customVersion": "[parameters('customVersion')]",
                "source": {
                    "kind": "SourceRepository",
                    "name": "Repositories",
                    "sourceId": "[parameters('sourceControlId')]"
                }
            }
        }
    ]
}
"@ | Out-File -FilePath $metadataFilePath

$resourceTypes = $contentTypes.Split(",") | ForEach-Object { $contentTypeMapping[$_] } | ForEach-Object { $_.ToLower() }
$MaxRetries = 3
$secondsBetweenAttempts = 5

#Converts hashtable to string that can be set as content when pushing csv file
function ConvertTableToString {
    $output = "FileName, CommitSha`n"
    $global:updatedCsvTable.GetEnumerator() | ForEach-Object {
        $key = RelativePathWithBackslash $_.Key
        $output += "{0},{1}`n" -f $key, $_.Value
    }
    return $output
}

$header = @{
    "authorization" = "Bearer $githubAuthToken"
}

#Gets all files and commit shas using Get Trees API
function GetGithubTree {
    $branchResponse = AttemptInvokeRestMethod "Get" "https://api.github.com/repos/$githubRepository/branches/$branchName" $null $null 3
    $treeUrl = "https://api.github.com/repos/$githubRepository/git/trees/" + $branchResponse.commit.sha + "?recursive=true"
    $getTreeResponse = AttemptInvokeRestMethod "Get" $treeUrl $null $null 3
    return $getTreeResponse
}

#Creates a table using the reponse from the tree api, creates a table
function GetCommitShaTable($getTreeResponse) {
    $shaTable = @{}
    $supportedExtensions = @(".json", ".bicep", ".bicepparam");
    $getTreeResponse.tree | ForEach-Object {
        $truePath = AbsolutePathWithSlash $_.path
        if ((([System.IO.Path]::GetExtension($_.path) -in $supportedExtensions)) -or ($truePath -eq $configPath))
        {
            $shaTable.Add($truePath, $_.sha)
        }
    }
    return $shaTable
}

function PushCsvToRepo() {
    $content = ConvertTableToString
    # Extract just the filename from csvPath and construct the correct relative path
    $csvFileName = Split-Path $csvPath -Leaf
    $subdirectoryName = Split-Path $rootDirectory -Leaf
    $relativeCsvPath = "$subdirectoryName\.sentinel\$csvFileName"
    $resourceBranchExists = git ls-remote --heads "https://github.com/$githubRepository" $newResourceBranch | wc -l

    if ($resourceBranchExists -eq 0) {
        git switch --orphan $newResourceBranch
        git commit --allow-empty -m "Initial commit on orphan branch"
        git push -u origin $newResourceBranch
        # Ensure the .sentinel directory exists in the correct location
        $sentinelDir = Split-Path $csvPath -Parent
        if (-not (Test-Path $sentinelDir)) {
            New-Item -ItemType "directory" -Path $sentinelDir -Force
        }
    } else {
        git fetch > $null
        git checkout $newResourceBranch
    }

    # Ensure the .sentinel directory exists before writing the CSV
    $sentinelDir = Split-Path $csvPath -Parent
    if (-not (Test-Path $sentinelDir)) {
        New-Item -ItemType "directory" -Path $sentinelDir -Force
    }

    Write-Output $content > $relativeCsvPath
    git add $relativeCsvPath
    git commit -m "Modified tracking table"
    git push -u origin $newResourceBranch
    git checkout $branchName
}

function ReadCsvToTable {
    if (-not (Test-Path $csvPath)) {
        Write-Host "[Info] CSV tracking file not found at $csvPath, starting with empty table"
        return @{}
    }
    
    try {
        $csvTable = Import-Csv -Path $csvPath
        $HashTable=@{}
        foreach($r in $csvTable)
        {
            $key = AbsolutePathWithSlash $r.FileName
            $HashTable[$key]=$r.CommitSha
        }
        return $HashTable
    }
    catch {
        Write-Host "[Warning] Failed to read CSV file $csvPath, starting with empty table. Error: $_"
        return @{}
    }
}

function AttemptInvokeRestMethod($method, $url, $body, $contentTypes, $maxRetries) {
    $Stoploop = $false
    $retryCount = 0
    do {
        try {
            $result = Invoke-RestMethod -Uri $url -Method $method -Headers $header -Body $body -ContentType $contentTypes
            $Stoploop = $true
        }
        catch {
            if ($retryCount -gt $maxRetries) {
                Write-Host "[Error] API call failed after $retryCount retries: $_"
                $Stoploop = $true
            }
            else {
                Write-Host "[Warning] API call failed: $_.`n Conducting retry #$retryCount."
                Start-Sleep -Seconds 5
                $retryCount = $retryCount + 1
            }
        }
    }
    While ($Stoploop -eq $false)
    return $result
}

function AttemptDeployMetadata($deploymentName, $resourceGroupName, $templateObject, $templateType, $paramFileType, $containsWorkspaceParam) {
    $deploymentInfo = $null
    try {
        $deploymentInfo = Get-AzResourceGroupDeploymentOperation -DeploymentName $deploymentName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
    }
    catch {
        Write-Host "[Warning] Unable to fetch deployment info for $deploymentName, no metadata was created for the resources in the file. Error: $_"
        return
    }
    $deploymentInfo | Where-Object { $_.TargetResource -ne "" } | ForEach-Object {
        $resource = $_.TargetResource
        $sentinelContentKinds = GetContentKinds $resource
        if ($sentinelContentKinds.Count -gt 0) {
            $contentKind = ToContentKind $sentinelContentKinds $resource $templateObject
            $contentId = $resource.Split("/")[-1]
            $metadataCustomVersion = GetMetadataCustomVersion $templateType $paramFileType $containsWorkspaceParam

            $isSuccess = $false
            $currentAttempt = 0

            While (($currentAttempt -lt $MaxRetries) -and (-not $isSuccess))
            {
                $currentAttempt ++
                Try
                {
                    New-AzResourceGroupDeployment -Name "md-$deploymentName" -ResourceGroupName $ResourceGroupName -TemplateFile $metadataFilePath `
                        -parentResourceId $resource `
                        -kind $contentKind `
                        -contentId $contentId `
                        -sourceControlId $sourceControlId `
                        -workspace $workspaceName `
                        -customVersion $metadataCustomVersion `
                        -ErrorAction Stop | Out-Host
                    Write-Host "[Info] Created metadata for $contentKind with parent resource id $resource"
                    $isSuccess = $true
                }
                Catch [Exception]
                {
                    $err = $_
                    if (-not (IsRetryable "md-$deploymentName"))
                    {
                        Write-Host "[Warning] Failed to deploy metadata for $contentKind with parent resource id $resource with error: $err"
                        break
                    }
                    else
                    {
                        if ($currentAttempt -le $MaxRetries)
                        {
                            Write-Host "[Warning] Failed to deploy metadata for $contentKind with error: $err. Retrying in $secondsBetweenAttempts seconds..."
                            Start-Sleep -Seconds $secondsBetweenAttempts
                        }
                        else
                        {
                            Write-Host "[Warning] Failed to deploy metadata for $contentKind after $currentAttempt attempts with error: $err"
                        }
                    }
                }
            }
        }
    }
}

function GetMetadataCustomVersion($templateType, $paramFileType, $containsWorkspaceParam){
    $customVersion = $templateType + "-" + $paramFileType
    if($containsWorkspaceParam){
        $customVersion += "-WorkspaceParam"
    }
    if($smartDeployment -eq "true"){
        $customVersion += "-SmartTracking"
    }
    return $customVersion
}

function GetContentKinds($resource) {
    return $sentinelResourcePatterns.Keys | Where-Object { $resource -match $sentinelResourcePatterns[$_] }
}

function ToContentKind($contentKinds, $resource, $templateObject) {
    if ($contentKinds.Count -eq 1) {
       return $contentKinds
    }
    if ($null -ne $resource -and $resource.Contains('savedSearches')) {
       if ($templateObject.resources.properties.Category -eq "Hunting Queries") {
           return "HuntingQuery"
       }
       return "Parser"
    }
    return $null
}

function IsValidTemplate($path, $templateObject, $parameterFile) {
    Try {
        if (DoesContainWorkspaceParam $templateObject) {
            if ($parameterFile) {
                Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $path -TemplateParameterFile $parameterFile -workspace $WorkspaceName
            }
            else {
                Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $path -workspace $WorkspaceName
            }
        }
        else {
            if ($parameterFile) {
                Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $path -TemplateParameterFile $parameterFile
            } else {
                Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $path
            }
        }

        return $true
    }
    Catch {
        Write-Host "[Warning] The file $path is not valid: $_"
        return $false
    }
}

function IsRetryable($deploymentName) {
    $retryableStatusCodes = "Conflict","TooManyRequests","InternalServerError","DeploymentActive"
    Try {
        $deploymentResult = Get-AzResourceGroupDeploymentOperation -DeploymentName $deploymentName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        return $retryableStatusCodes -contains $deploymentResult.StatusCode
    }
    Catch {
        return $false
    }
}

function IsValidResourceType($template) {
    try {
        $isAllowedResources = $true
        $template.resources | ForEach-Object {
            $isAllowedResources = $resourceTypes.contains($_.type.ToLower()) -and $isAllowedResources
        }
    }
    catch {
        Write-Host "[Error] Failed to check valid resource type."
        $isAllowedResources = $false
    }
    return $isAllowedResources
}

function DoesContainWorkspaceParam($templateObject) {
    $templateObject.parameters.PSobject.Properties.Name -contains "workspace"
}

function AttemptDeployment($path, $parameterFile, $deploymentName, $templateObject, $templateType) {
    Write-Host "[Info] Deploying $path with deployment name $deploymentName"

    $isValid = IsValidTemplate $path $templateObject $parameterFile
    if (-not $isValid) {
        Write-Host "[Error] Not deploying $path since the template is not valid"
        return $false
    }
    $isSuccess = $false
    $currentAttempt = 0
    While (($currentAttempt -lt $MaxRetries) -and (-not $isSuccess))
    {
        $currentAttempt ++
        Try
        {
            Write-Host "[Info] Deploy $path with parameter file: [$parameterFile]"
            $paramFileType = if(!$parameterFile) {"NoParam"} elseif($parameterFile -like "*.bicepparam") {"BicepParam"} else {"JsonParam"}
            $containsWorkspaceParam = DoesContainWorkspaceParam $templateObject
            if ($containsWorkspaceParam)
            {
                if ($parameterFile) {
                    New-AzResourceGroupDeployment -Name $deploymentName -ResourceGroupName $ResourceGroupName -TemplateFile $path -workspace $workspaceName -TemplateParameterFile $parameterFile -ErrorAction Stop | Out-Host
                }
                else
                {
                    New-AzResourceGroupDeployment -Name $deploymentName -ResourceGroupName $ResourceGroupName -TemplateFile $path -workspace $workspaceName -ErrorAction Stop | Out-Host
                }
            }
            else
            {
                if ($parameterFile) {
                    New-AzResourceGroupDeployment -Name $deploymentName -ResourceGroupName $ResourceGroupName -TemplateFile $path -TemplateParameterFile $parameterFile -ErrorAction Stop | Out-Host
                }
                else
                {
                    New-AzResourceGroupDeployment -Name $deploymentName -ResourceGroupName $ResourceGroupName -TemplateFile $path -ErrorAction Stop | Out-Host
                }
            }
            AttemptDeployMetadata $deploymentName $ResourceGroupName $templateObject $templateType $paramFileType $containsWorkspaceParam

            $isSuccess = $true
        }
        Catch [Exception]
        {
            $err = $_
            if (-not (IsRetryable $deploymentName))
            {
                Write-Host "[Warning] Failed to deploy $path with error: $err"
                break
            }
            else
            {
                if ($currentAttempt -le $MaxRetries)
                {
                    Write-Host "[Warning] Failed to deploy $path with error: $err. Retrying in $secondsBetweenAttempts seconds..."
                    Start-Sleep -Seconds $secondsBetweenAttempts
                }
                else
                {
                    Write-Host "[Warning] Failed to deploy $path after $currentAttempt attempts with error: $err"
                }
            }
        }
    }
    return $isSuccess
}

function GenerateDeploymentName() {
    $randomId = [guid]::NewGuid()
    return "Sentinel_Deployment_$randomId"
}

#Load deployment configuration
function LoadDeploymentConfig() {
    Write-Host "[Info] load the deployment configuration from [$configPath]"
    $global:parameterFileMapping = @{}
    $global:prioritizedContentFiles = @()
    $global:excludeContentFiles = @()
    try {
        if (Test-Path $configPath) {
            $deployment_config = Get-Content $configPath | Out-String | ConvertFrom-Json
            $parameterFileMappings = @{}
            if ($deployment_config.parameterfilemappings) {
                $deployment_config.parameterfilemappings.psobject.properties | ForEach { $parameterFileMappings[$_.Name] = $_.Value }
            }
            $key = ($parameterFileMappings.Keys | ? { $_ -eq $workspaceId })
            if ($null -ne $key) {
                $parameterFileMappings[$key].psobject.properties | ForEach { $global:parameterFileMapping[$_.Name] = $_.Value }
            }
            if ($deployment_config.prioritizedcontentfiles) {
                $global:prioritizedContentFiles = $deployment_config.prioritizedcontentfiles
            }
            $excludeList = $global:parameterFileMapping.Values + $global:prioritizedcontentfiles
            if ($deployment_config.excludecontentfiles) {
                $excludeList = $excludeList + $deployment_config.excludecontentfiles
            }
            $global:excludeContentFiles = $excludeList | Where-Object { Test-Path (AbsolutePathWithSlash $_) }
        }
    }
    catch {
        Write-Host "[Warning] An error occurred while trying to load deployment configuration."
        Write-Host "Exception details: $_"
        Write-Host $_.ScriptStackTrace
    }
}

function filterContentFile($fullPath) {
	$temp = RelativePathWithBackslash $fullPath
	return $global:excludeContentFiles | Where-Object {$temp.StartsWith($_, 'CurrentCultureIgnoreCase')}
}

function RelativePathWithBackslash($absolutePath) {
	return $absolutePath.Replace($rootDirectory + "\", "").Replace("\", "/")
}

function AbsolutePathWithSlash($relativePath) {
	return Join-Path -Path $rootDirectory -ChildPath $relativePath
}

#resolve parameter file name, return $null if there is none.
function GetParameterFile($path) {
    if ($path.Length -eq 0) {
        return $null
    }

    $index = RelativePathWithBackslash $path
    $key = ($global:parameterFileMapping.Keys | Where-Object { $_ -eq $index })
    if ($key) {
        $mappedParameterFile = AbsolutePathWithSlash $global:parameterFileMapping[$key]
        if (Test-Path $mappedParameterFile) {
            return $mappedParameterFile
        }
    }

    $extension = [System.IO.Path]::GetExtension($path)
    if ($extension -ne ".json" -and $extension -ne ".bicep") {
        return $null
    }

    $parameterFilePrefix = $path.Substring(0, $path.Length - $extension.Length)

    # Check for workspace-specific parameter file
    if ($extension -eq ".bicep") {
        $workspaceParameterFile = $parameterFilePrefix + "-$WorkspaceId.bicepparam"
        if (Test-Path $workspaceParameterFile) {
            return $workspaceParameterFile
        }
    }

    $workspaceParameterFile = $parameterFilePrefix + ".parameters-$WorkspaceId.json"
    if (Test-Path $workspaceParameterFile) {
        return $workspaceParameterFile
    }

    # Check for parameter file
    if ($extension -eq ".bicep") {
        $defaultParameterFile = $parameterFilePrefix + ".bicepparam"
        Write-Host "Default parameter file: $defaultParameterFile"
        if (Test-Path $defaultParameterFile) {
            return $defaultParameterFile
        }
    }

    $defaultParameterFile = $parameterFilePrefix + ".parameters.json"
    Write-Host "Default parameter file: $defaultParameterFile"
    if (Test-Path $defaultParameterFile) {
        return $defaultParameterFile
    }

    return $null
}

function CheckRuleExistsInSentinel($templateObject) {
    # Extract rule information from template
    try {
        if ($templateObject.resources -and $templateObject.resources.Length -gt 0) {
            $resource = $templateObject.resources[0]
            
            # Extract rule ID from multiple possible locations
            $ruleId = $null
            
            # Method 1: Extract from 'id' field (ARM template expression)
            if ($resource.id) {
                $idPattern = $resource.id
                # Look for GUID at the end of the ARM expression: /alertRules/GUID')]
                if ($idPattern -match "/alertRules/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
                    $ruleId = $matches[1]
                    Write-Host "[Info] Extracted rule ID from 'id' field: $ruleId"
                }
            }
            
            # Method 2: Extract from 'name' field (fallback)
            if (-not $ruleId -and $resource.name) {
                $namePattern = $resource.name
                if ($namePattern -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
                    $ruleId = $matches[1]
                    Write-Host "[Info] Extracted rule ID from 'name' field: $ruleId"
                }
            }
            
            if ($ruleId) {
                Write-Host "[Info] Checking if rule with ID '$ruleId' already exists in Sentinel"
                
                # Try to get the rule from Sentinel
                try {
                    $existingRule = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -RuleId $ruleId -ErrorAction SilentlyContinue
                    if ($existingRule) {
                        Write-Host "[Info] Rule with ID '$ruleId' already exists in Sentinel. Display Name: '$($existingRule.DisplayName)'"
                        return $true
                    } else {
                        Write-Host "[Info] Rule with ID '$ruleId' does not exist in Sentinel"
                        return $false
                    }
                }
                catch {
                    # If Az.SecurityInsights cmdlet fails, try alternative method using generic Get-AzResource
                    Write-Host "[Warning] Az.SecurityInsights cmdlet failed, trying generic Get-AzResource. Error: $_"
                    try {
                        $resourceName = "$WorkspaceName/Microsoft.SecurityInsights/$ruleId"
                        $existingRule = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.OperationalInsights/workspaces/providers/alertRules" -Name $resourceName -ErrorAction SilentlyContinue
                        if ($existingRule) {
                            Write-Host "[Info] Rule with ID '$ruleId' already exists in Sentinel (found via Get-AzResource)"
                            return $true
                        } else {
                            Write-Host "[Info] Rule with ID '$ruleId' does not exist in Sentinel"
                            return $false
                        }
                    }
                    catch {
                        Write-Host "[Warning] Could not check rule existence using Get-AzResource. Error: $_"
                        # If we can't check, assume it doesn't exist to allow deployment
                        return $false
                    }
                }
            } else {
                Write-Host "[Warning] Could not extract rule ID from template"
                return $false
            }
        } else {
            Write-Host "[Warning] No resources found in template"
            return $false
        }
    }
    catch {
        Write-Host "[Warning] Error checking rule existence: $_"
        return $false
    }
}

function ExtractRuleIdFromJsonContent($jsonContent) {
    # Extract rule ID from JSON content for deleted files
    try {
        if ($jsonContent.resources -and $jsonContent.resources.Length -gt 0) {
            $resource = $jsonContent.resources[0]
            $ruleId = $null
            
            # Method 1: Extract from 'id' field (ARM template expression)
            if ($resource.id) {
                $idPattern = $resource.id
                # Look for GUID at the end of the ARM expression: /alertRules/GUID')]
                if ($idPattern -match "/alertRules/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
                    $ruleId = $matches[1]
                    Write-Host "[Info] Successfully extracted rule ID from 'id' field: $ruleId"
                    return $ruleId
                }
            }
            
            # Method 2: Extract from 'name' field (fallback)
            if (-not $ruleId -and $resource.name) {
                $namePattern = $resource.name
                if ($namePattern -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
                    $ruleId = $matches[1]
                    Write-Host "[Info] Successfully extracted rule ID from 'name' field: $ruleId"
                    return $ruleId
                }
            }
            
            # Method 3: Look for any GUID pattern in the entire resource object (last resort)
            if (-not $ruleId) {
                $resourceJson = $resource | ConvertTo-Json -Depth 10
                if ($resourceJson -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
                    $ruleId = $matches[1]
                    Write-Host "[Info] Successfully extracted rule ID from resource JSON pattern: $ruleId"
                    return $ruleId
                }
            }
            
            if (-not $ruleId) {
                Write-Host "[Warning] Could not find GUID pattern in resource"
            }
        } else {
            Write-Host "[Warning] No resources found in JSON content"
        }
    }
    catch {
        Write-Host "[Warning] Error extracting rule ID from JSON content: $_"
    }
    return $null
}

function ExtractRuleIdFromDeletedFile($relativePath) {
    # Try to get the rule ID from previous commit
    try {
        $previousFileContent = git show "HEAD~1:$relativePath" 2>$null
        if ($previousFileContent) {
            # Remove BOM if present and clean up the content
            $cleanContent = $previousFileContent -replace '^\uFEFF', '' -replace '^\ufeff', ''
            $cleanContent = $cleanContent.Trim()
            
            if ([string]::IsNullOrWhiteSpace($cleanContent)) {
                Write-Host "[Warning] Previous commit content is empty for $relativePath"
                return $null
            }
            
            $jsonContent = $cleanContent | ConvertFrom-Json
            $ruleId = ExtractRuleIdFromJsonContent $jsonContent
            if ($ruleId) {
                return $ruleId
            }
        } else {
            Write-Host "[Warning] Could not retrieve previous commit content for $relativePath"
        }
    }
    catch {
        Write-Host "[Warning] Could not extract rule ID from deleted file $relativePath from previous commit. Error: $_"
        
        # Alternative approach: try to extract GUID from filename if present
        if ($relativePath -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
            Write-Host "[Info] Found GUID in filename: $($matches[1])"
            return $matches[1]
        }
    }
    return $null
}

function DeleteSentinelRule($ruleId) {
    try {
        $ruleName = "$WorkspaceName/Microsoft.SecurityInsights/$ruleId"
        Write-Host "[Info] Attempting to delete Sentinel rule: $ruleName"
        
        # Check if the rule exists first
        try {
            $existingRule = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.OperationalInsights/workspaces/providers/alertRules" -Name $ruleName -ErrorAction Stop
            Write-Host "[Info] Found existing rule $ruleName, proceeding with deletion"
        }
        catch {
            Write-Host "[Warning] Rule $ruleName not found in Sentinel, it may have already been deleted. Error: $_"
            return $true
        }
        
        # Attempt to delete the rule using the Security Insights cmdlet
        $isSuccess = $false
        $currentAttempt = 0
        
        While (($currentAttempt -lt $MaxRetries) -and (-not $isSuccess)) {
            $currentAttempt++
            Try {
                # Try using the Security Insights specific removal cmdlet first
                try {
                    Remove-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -RuleId $ruleId -ErrorAction Stop
                    Write-Host "[Info] Successfully deleted Sentinel rule using Az.SecurityInsights: $ruleId"
                    $isSuccess = $true
                }
                catch {
                    Write-Host "[Warning] Az.SecurityInsights cmdlet failed, trying generic Remove-AzResource. Error: $_"
                    # Fallback to generic resource removal
                    Remove-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.OperationalInsights/workspaces/providers/alertRules" -Name $ruleName -Force -ErrorAction Stop
                    Write-Host "[Info] Successfully deleted Sentinel rule using Remove-AzResource: $ruleName"
                    $isSuccess = $true
                }
            }
            Catch [Exception] {
                $err = $_
                if ($currentAttempt -le $MaxRetries) {
                    Write-Host "[Warning] Failed to delete rule $ruleName (attempt $currentAttempt/$MaxRetries). Error: $err. Retrying in $secondsBetweenAttempts seconds..."
                    Start-Sleep -Seconds $secondsBetweenAttempts
                }
                else {
                    Write-Host "[Error] Failed to delete rule $ruleName after $currentAttempt attempts. Error: $err"
                }
            }
        }
        
        # Also try to delete associated metadata if it exists
        try {
            $metadataName = "analyticsrule-$ruleId"
            $metadataResourceName = "$WorkspaceName/Microsoft.SecurityInsights/$metadataName"
            Remove-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.OperationalInsights/workspaces/providers/metadata" -Name $metadataResourceName -Force -ErrorAction SilentlyContinue
            Write-Host "[Info] Attempted to delete metadata for rule: $metadataName"
        }
        catch {
            Write-Host "[Warning] Could not delete metadata for rule $ruleId. This is not critical. Error: $_"
        }
        
        return $isSuccess
    }
    catch {
        Write-Host "[Error] Failed to delete Sentinel rule $ruleId. Error: $_"
        return $false
    }
}

function ProcessDeletedFiles() {
    if ([string]::IsNullOrEmpty($DeletedFiles)) {
        Write-Host "[Info] No files were deleted"
        return
    }
    
    Write-Host "[Info] Processing deleted files: $DeletedFiles"
    $deletedFileArray = $DeletedFiles -split ','
    $totalDeleted = 0
    $totalDeleteFailed = 0
    
    $deletedFileArray | ForEach-Object {
        $relativePath = $_.Trim()
        if (-not [string]::IsNullOrEmpty($relativePath)) {
            Write-Host "[Info] Processing deleted file: $relativePath"
            
            # Extract rule ID from the deleted file
            $ruleId = ExtractRuleIdFromDeletedFile $relativePath
            
            if ($ruleId) {
                Write-Host "[Info] Extracted rule ID '$ruleId' from deleted file $relativePath"
                $deleteSuccess = DeleteSentinelRule $ruleId
                
                if ($deleteSuccess) {
                    $totalDeleted++
                    Write-Host "[Info] Successfully processed deletion of rule $ruleId"
                    
                    # Remove from tracking table if it exists - handle path prefixes correctly
                    $fileName = $relativePath
                    if ($relativePath.StartsWith("Tenants/WizardCyber/")) {
                        $fileName = $relativePath.Substring("Tenants/WizardCyber/".Length)
                    } elseif ($relativePath.StartsWith("BaseRuleSet/")) {
                        $fileName = $relativePath.Substring("BaseRuleSet/".Length)
                    }
                    $absolutePath = Join-Path $rootDirectory $fileName
                    if ($global:updatedCsvTable.ContainsKey($absolutePath)) {
                        $global:updatedCsvTable.Remove($absolutePath)
                        Write-Host "[Info] Removed $absolutePath from tracking table"
                    }
                }
                else {
                    $totalDeleteFailed++
                    Write-Host "[Error] Failed to delete rule $ruleId from Sentinel"
                }
            }
            else {
                Write-Host "[Warning] Could not extract rule ID from deleted file: $relativePath"
                $totalDeleteFailed++
            }
        }
    }
    
    Write-Host "[Info] Deletion summary: $totalDeleted successful, $totalDeleteFailed failed"
    
    if ($totalDeleteFailed -gt 0) {
        Write-Host "[Warning] Some rule deletions failed. Check the logs above for details."
    }
}

function SmartDeployment($fullDeploymentFlag, $remoteShaTable, $path, $parameterFile, $templateObject, $templateType) {
    try {
        $skip = $false
        $isSuccess = $null
        
        # Check if rule already exists in Sentinel (for logging purposes only)
        $ruleExists = CheckRuleExistsInSentinel $templateObject
        if ($ruleExists) {
            Write-Host "[Info] Rule already exists in Sentinel - will update it with new changes from $path"
        } else {
            Write-Host "[Info] Rule does not exist in Sentinel - will create new rule from $path"
        }
        
        if (!$fullDeploymentFlag) {
            $existingSha = $global:localCsvTablefinal[$path]
            $remoteSha = $remoteShaTable[$path]
            $skip = (($existingSha) -and ($existingSha -eq $remoteSha))
            if ($skip -and $parameterFile) {
                $existingShaForParameterFile = $global:localCsvTablefinal[$parameterFile]
                $remoteShaForParameterFile = $remoteShaTable[$parameterFile]
                $skip = (($existingShaForParameterFile) -and ($existingShaForParameterFile -eq $remoteShaForParameterFile))
            }
        }
        if (!$skip) {
            $deploymentName = GenerateDeploymentName
            $isSuccess = AttemptDeployment $path $parameterFile $deploymentName $templateObject $templateType
        }
        return @{
            skip = $skip
            isSuccess = $isSuccess
            reason = if ($skip) { "SHA comparison indicates no changes" } else { "Deployment attempted" }
        }
    }
    catch {
        Write-Host "[Error] An error occurred while trying to deploy file $path. Exception details: $_"
        Write-Host $_.ScriptStackTrace
    }
}

function Deployment($fullDeploymentFlag, $remoteShaTable, $tree) {
    Write-Host "Starting Deployment for Files in path: $Directory"
    if (Test-Path -Path $Directory)
    {
        $totalFiles = 0;
        $totalFailed = 0;
        $iterationList = @()
        
        # If we have specific changed files, only deploy those
        if (-not [string]::IsNullOrEmpty($ChangedFiles)) {
            Write-Host "[Info] Selective deployment mode - only deploying changed files: $ChangedFiles"
            $changedFileArray = $ChangedFiles -split ','
            $changedFileArray | ForEach-Object {
                $relativePath = $_.Trim()
                if (-not [string]::IsNullOrEmpty($relativePath)) {
                    # Handle path prefixes correctly - remove directory prefix if present since rootDirectory already points to the target directory
                    $fileName = $relativePath
                    if ($relativePath.StartsWith("Tenants/WizardCyber/")) {
                        $fileName = $relativePath.Substring(Tenants/"WizardCyber/".Length)
                    } elseif ($relativePath.StartsWith("BaseRuleSet/")) {
                        $fileName = $relativePath.Substring("BaseRuleSet/".Length)
                    }
                    $absolutePath = Join-Path $rootDirectory $fileName
                    if (Test-Path $absolutePath) {
                        Write-Host "[Info] Adding changed file to deployment: $absolutePath"
                        $iterationList += $absolutePath
                    } else {
                        Write-Host "[Warning] Changed file not found: $absolutePath"
                        Write-Host "[Debug] Tried path: $absolutePath (from relativePath: $relativePath, fileName: $fileName, rootDirectory: $rootDirectory)"
                    }
                }
            }
        } else {
            # Fallback to original behavior for full deployment
            Write-Host "[Info] Full deployment mode - deploying all files"
            $global:prioritizedContentFiles | ForEach-Object  { $iterationList += (AbsolutePathWithSlash $_) }
            Get-ChildItem -Path $Directory -Recurse -Include *.bicep, *.json -exclude *metadata.json, *.parameters*.json, *.bicepparam, bicepconfig.json |
                            Where-Object { $null -eq ( filterContentFile $_.FullName ) } |
                            Select-Object -Property FullName |
                            ForEach-Object { $iterationList += $_.FullName }
        }
        
        Write-Host "[Info] Total files to deploy: $($iterationList.Count)"
        $iterationList | ForEach-Object {
            $path = $_
            Write-Host "[Info] Try to deploy $path"
            if (-not (Test-Path $path)) {
                Write-Host "[Warning] Skipping deployment for $path. The file doesn't exist."
                return
            }

            if ($path -like "*.bicep") {
                $templateType = "Bicep"
                $templateObject = bicep build $path --stdout | Out-String | ConvertFrom-Json
            } else {
                $templateType = "ARM"
                $templateObject = Get-Content $path | Out-String | ConvertFrom-Json
            }

            if (-not (IsValidResourceType $templateObject))
            {
                Write-Host "[Warning] Skipping deployment for $path. The file contains resources for content that was not selected for deployment. Please add content type to connection if you want this file to be deployed."
                return
            }
            $parameterFile = GetParameterFile $path
            $result = SmartDeployment $fullDeploymentFlag $remoteShaTable $path $parameterFile $templateObject $templateType
            
            # Log the deployment result and reason
            if ($result.reason) {
                Write-Host "[Info] Deployment result for $($path): $($result.reason)"
            }
            
            if ($result.isSuccess -eq $false) {
                $totalFailed++
            }
            if (-not $result.skip) {
                $totalFiles++
            }
            if ($result.isSuccess -or $result.skip) {
                $global:updatedCsvTable[$path] = $remoteShaTable[$path]
                if ($parameterFile) {
                    $global:updatedCsvTable[$parameterFile] = $remoteShaTable[$parameterFile]
                }
            }
        }
        PushCsvToRepo
        if ($totalFiles -gt 0 -and $totalFailed -gt 0)
        {
            $err = "$totalFailed of $totalFiles deployments failed."
            Throw $err
        }
    }
    else
    {
        Write-Output "[Warning] $Directory not found. nothing to deploy"
    }
}

function SmartDeployment($fullDeploymentFlag, $remoteShaTable, $path, $parameterFile, $templateObject, $templateType) {
    try {
        $skip = $false
        $isSuccess = $null
        if (!$fullDeploymentFlag) {
            $existingSha = $global:localCsvTablefinal[$path]
            $remoteSha = $remoteShaTable[$path]
            $skip = (($existingSha) -and ($existingSha -eq $remoteSha))
            if ($skip -and $parameterFile) {
                $existingShaForParameterFile = $global:localCsvTablefinal[$parameterFile]
                $remoteShaForParameterFile = $remoteShaTable[$parameterFile]
                $skip = (($existingShaForParameterFile) -and ($existingShaForParameterFile -eq $remoteShaForParameterFile))
            }
        }
        if (!$skip) {
            $deploymentName = GenerateDeploymentName
            $isSuccess = AttemptDeployment $path $parameterFile $deploymentName $templateObject $templateType
        }
        return @{
            skip = $skip
            isSuccess = $isSuccess
        }
    }
    catch {
        Write-Host "[Error] An error occurred while trying to deploy file $path. Exception details: $_"
        Write-Host $_.ScriptStackTrace
    }
}

function TryGetCsvFile {
    # Initialize with empty table in case no CSV exists
    $global:localCsvTablefinal = @{}
    
    if (Test-Path $csvPath) {
        $global:localCsvTablefinal = ReadCsvToTable
        Remove-Item -Path $csvPath
        git add $csvPath
        git commit -m "Removed tracking file and moved to new sentinel created branch"
        git push origin $branchName
    }

    # Extract just the filename from csvPath and construct the correct relative path
    $csvFileName = Split-Path $csvPath -Leaf
    $subdirectoryName = Split-Path $rootDirectory -Leaf
    $relativeCsvPath = "$subdirectoryName\.sentinel\$csvFileName"
    $resourceBranchExists = git ls-remote --heads "https://github.com/$githubRepository" $newResourceBranch | wc -l

    if ($resourceBranchExists -eq 1) {
        git fetch > $null
        git checkout $newResourceBranch

        if (Test-Path $relativeCsvPath) {
            $global:localCsvTablefinal = ReadCsvToTable
        }
        git checkout $branchName
    }
}

function main() {
    git config --global user.email "donotreply@microsoft.com"
    git config --global user.name "Sentinel"

    # Debug: Print environment variables
    Write-Host "[Debug] Environment Variables:"
    Write-Host "[Debug] rootDirectory: $rootDirectory"
    Write-Host "[Debug] Directory: $Directory"
    Write-Host "[Debug] csvPath: $csvPath"
    Write-Host "[Debug] ChangedFiles: '$ChangedFiles'"
    Write-Host "[Debug] DeletedFiles: '$DeletedFiles'"
    Write-Host "[Debug] smartDeployment: $smartDeployment"
    Write-Host "[Debug] WorkspaceName: $WorkspaceName"
    Write-Host "[Debug] ResourceGroupName: $ResourceGroupName"

    # Early exit if no files changed and we're in selective mode
    if (-not [string]::IsNullOrEmpty($ChangedFiles)) {
        Write-Host "[Info] Selective deployment mode detected with changed files: $ChangedFiles"
    } elseif (-not [string]::IsNullOrEmpty($DeletedFiles)) {
        Write-Host "[Info] Selective deletion mode detected with deleted files: $DeletedFiles"
    } elseif ($smartDeployment -eq "true") {
        Write-Host "[Info] No specific files changed or deleted and smart deployment is enabled. Checking for changes using SHA comparison."
    }

    TryGetCsvFile
    LoadDeploymentConfig
    $tree = GetGithubTree
    $remoteShaTable = GetCommitShaTable $tree

    $existingConfigSha = $global:localCsvTablefinal[$configPath]
    $remoteConfigSha = $remoteShaTable[$configPath]
    $modifiedConfig = ($existingConfigSha -xor $remoteConfigSha) -or ($existingConfigSha -and $remoteConfigSha -and ($existingConfigSha -ne $remoteConfigSha))

    if ($remoteConfigSha) {
        $global:updatedCsvTable[$configPath] = $remoteConfigSha
    }

    # Only set fullDeploymentFlag for config changes, not for all deployments
    $fullDeploymentFlag = $modifiedConfig -or ($smartDeployment -eq "false")
    
    # If we have specific changed files, don't do full deployment even if config changed
    if (-not [string]::IsNullOrEmpty($ChangedFiles) -or -not [string]::IsNullOrEmpty($DeletedFiles)) {
        Write-Host "[Info] Using selective deployment - processing specific changed/deleted files"
        $fullDeploymentFlag = $false
    }
    
    # Process deleted files first
    ProcessDeletedFiles
    
    Deployment $fullDeploymentFlag $remoteShaTable $tree
}

main



# Adapted from https://github.com/mcbobke/PlasterModuleTemplate
Param(
    [string]$ModuleName,
    [string]$VersionIncrement,
    [switch]$Coverage,
    [string]$PatToken,
    [switch]$Prerelease,
    [switch]$ValidateCoverage,
    [string]$RepoName
)

# Synopsis: Runs full Build and Test process
Task Default Build, Test

# Synopsis: Run pipeline tasks
Task Pipeline VerifyTriggeringBranch, PackageModule

# Synopsis: Builds the [dist] directory and prepares the module for testing and publishing
Task Build Clean, CopyDist, InstallModuleDependencies, GetReleasedModuleInfo, BuildPSM1, BuildPSD1

# Synopsis: Runs a new build and imports the resulting module
Task Import Build, {
    Write-Output "  Removing loaded module [$ModuleName]"
    Remove-Module -Name $ModuleName -Force -Verbose:$VerbosePreference -ErrorAction SilentlyContinue
    Write-Output "  Import module from path [$Script:ManifestPath]"
    Import-Module -Name $Script:ManifestPath -Force -Verbose:$VerbosePreference
}

Enter-Build {
    function GetPatTokenCreds {
        param (
            [string]$PatToken
        )
        $password = ConvertTo-SecureString -String $PatToken -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential ('DevOps', $password)
    }

    function Invoke-ADOWebRequest {
        [CmdletBinding()]
        param (
            $Url,
            $Body,
            $PatToken,
            $OutFile,
            $Method='Get'
        )
        $authToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($PatToken)"))
        $response = Invoke-RestMethod -Method $Method -Uri $Url -Headers @{Authorization = "Basic $authToken"; 'Content-Type' = 'application/json'} -Body $Body -OutFile $OutFile
        if ($response -match 'Azure DevOps Services | Sign In') {
            throw "Failed to login to Azure, check PAT token!"
        } else {
            if ($response.value) {
                return $response.value
            } else {
                return $response
            }
        }
    }

    function GetPackageFeed ($Name, $PatToken) {
        $url = "https://feeds.dev.azure.com/deloittegti/_apis/packaging/feeds/$($Name)?api-version6.0-preview.1"
        Invoke-ADOWebRequest -Url $url -PatToken $PatToken
    }

    function GetAzureArtifactPackageInfo ($Name, $FeedID, [switch]$Latest, $PatToken) {
        $queries = @()
        $url = "https://feeds.dev.azure.com/deloittegti/_apis/packaging/Feeds/$($FeedID)/packages?"
        $queries += "packageNameQuery=$Name"
        $queries += "api-version=6.0-preview.1"

        if (-not $Latest) { $queries += "includeAllVersions=true" }

        $url += $queries -join '&'
        $response = Invoke-ADOWebRequest -Url $url -PatToken $PatToken

        return $response
    }

    function DownloadAzureArtifactPackage ($Name, $Version, $FeedID, $OutFile, $PatToken) {
        $url = "https://pkgs.dev.azure.com/deloittegti/_apis/packaging/feeds/$FeedID/nuget/packages/$Name/versions/$Version/content?api-version=6.0-preview.1"
        $response = Invoke-ADOWebRequest -Url $url -OutFile $OutFile -PatToken $PatToken
        return $response
    }

    function ExtractAzureArtifactPackage ($File, $DestinationPath) {
        Expand-Archive -Path $File -DestinationPath $DestinationPath -Force
        Remove-Item -Path $DestinationPath\_rels -Recurse -Force
        Remove-Item -Path $DestinationPath\package -Recurse -Force
        Remove-Item -Path "$DestinationPath\*.xml" -Force
        Remove-Item -Path "$DestinationPath\*.nuspec" -Force
    }

    function GetPreviousRelease {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [string]$Repository,

            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [switch]$PreferRelease,

            [Parameter()]
            [string]$PatToken
        )

        process {
            try {
                $feed = GetPackageFeed -Name $Repository -PatToken $PatToken
                $packageInfo = GetAzureArtifactPackageInfo -Name $Name -FeedID $feed.id -Latest -PatToken $PatToken
                $latestVersionInfo = $packageInfo.versions
                if ($PreferRelease -and $latestVersionInfo.version -like '*-prerelease') {
                    $packageInfo = GetAzureArtifactPackageInfo -Name $Name -FeedID $feed.id -PatToken $PatToken
                    $allVersions = $packageInfo.versions
                    $releaseVersions = $allVersions | Where-Object { $_.version -notlike '*-prerelease' } | Sort-Object -Property version -Descending
                    if ($releaseVersions) {
                        $packageVersion = $releaseVersions | Select-Object -First 1
                    } else {
                        $packageVersion = $latestVersionInfo
                    }
                } else {
                    $packageVersion = $latestVersionInfo
                }

                if ($packageVersion) {
                    $File = "$Path\$Name.zip"
                    $Destination = "$Path\$Name"
                    DownloadAzureArtifactPackage -FeedID $feed.id -Name $packageInfo.name -Version $packageVersion.version -OutFile $File -PatToken $PatToken
                    ExtractAzureArtifactPackage -File $File -DestinationPath $Destination
                }

                return $packageVersion
            } catch {
                $PSCmdlet.ThrowTerminatingError($_)
            }
        }
    }

    function GetPublicFunctionInterfaces {
        [CmdletBinding()]
        Param (
            [System.Management.Automation.FunctionInfo[]]$FunctionList
        )

        $functions = @{}

        $FunctionList | ForEach-Object {
            $function = $_

            $Parameters = @{}

            $function.Parameters.Keys | ForEach-Object {
                $parameterName = $_
                $parameter = $function.Parameters[$parameterName]
                $parameterAttribute = $parameter.Attributes | where {$_ -is [System.Management.Automation.ParameterAttribute]}
                $allowEmptyString = ($parameter.Attributes | ForEach-Object { $_.GetType().Name }) -contains 'AllowEmptyStringAttribute'
                $allowNull = ($parameter.Attributes | ForEach-Object { $_.GetType().Name }) -contains 'AllowNullAttribute'

                $paramInfo = [pscustomobject]@{
                    Type = $parameter.ParameterType.Name
                    Attributes = [pscustomobject]@{
                        Position = $parameterAttribute.Position
                        Mandatory = $parameterAttribute.Mandatory
                        AllowEmptyString = $allowEmptyString
                        AllowNull = $allowNull
                        ValueFromPipeline = $parameterAttribute.ValueFromPipeline
                        ValueFromPipelineByPropertyName = $parameterAttribute.ValueFromPipelineByPropertyName
                        ValueFromRemainingArguments = $parameterAttribute.ValueFromRemainingArguments
                    }
                    Aliases = [string[]]$parameter.Aliases
                }

                $Parameters[$parameterName] = $paramInfo
            }

            $functions[$function.Name] = $Parameters
        }

        $functions
    }

    function GetAzurePullRequest {
        param (
            $CommitHash,
            $PatToken
        )
        # $url = "https://dev.azure.com/deloittegti/gti-automation/_apis/git/pullrequests/$($PullRequestId)?api-version=6.0"
        # if ($Status) { $url += "&searchCriteria.status=$Status" }
        # if ($TargetRefName) { $url += "&searchCriteria.targetRefName=$TargetRefName" }
        $body = @"
{
    "queries": [{
        "items": [
            "$CommitHash"
        ],
        "type": "lastMergeCommit"
    }]
}
"@
        $url = 'https://dev.azure.com/deloittegti/gti-automation/_apis/git/repositories/d7b89b8b-3bc1-48f8-bf0d-fcd8978e96d2/pullrequestquery?api-version=6.1-preview.1'
        $response = Invoke-ADOWebRequest -Method Post -Url $url -Body $body -PatToken $PatToken
        return $response.results | Select-Object -ExpandProperty $CommitHash -ErrorAction SilentlyContinue
    }

    function GetPullRequestIdFromCommitMessage {
        $commit = git show-branch --no-name HEAD
        $prId = [regex]::Matches($commit, 'Merged PR (\d+):').groups | Select-Object -First 1 -Skip 1 -ExpandProperty Value
        return $prId
    }

    function ComparePublicFunctionInterfaces {
        param (
            $NewInterfaces,
            $OldInterfaces
        )

        Compare-Object -ReferenceObject $OldInterfaces -DifferenceObject $NewInterfaces
    }

    function GetModifiedFiles {
        param (
            [string]$ReferenceFolder,
            [string]$DifferenceFolder,
            [string[]]$Exclude
        )
        $Exclude = $Exclude | ForEach-Object { $_ -replace '\\','\\' }
        $ReferenceHashes = Get-ChildItem -Path "$ReferenceFolder" -Recurse |
            Where-Object { $_.FullName -notmatch ($Exclude -join '|') } |
            Get-FileHash
        $DifferenceHashes = Get-ChildItem -Path "$DifferenceFolder" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch ($Exclude -join '|') } |
            Get-FileHash
        $files = $ReferenceHashes + $DifferenceHashes

        foreach ($ReferenceHash in $ReferenceHashes) {
            foreach ($DifferenceHash in $DifferenceHashes) {
                if ($ReferenceHash.Hash -eq $DifferenceHash.Hash) {
                    $files = $files | Where-Object { $_.Path -ne $ReferenceHash.Path }
                    $files = $files | Where-Object { $_.Path -ne $DifferenceHash.Path }
                }
            }
        }

        $files | ForEach-Object { ($_.Path -split '\\')[-1] } | Select-Object -Unique
    }

    $Script:ProjectPath = Split-Path -Path $PSScriptRoot -Parent -Resolve
    $Script:BuildTools = Join-Path -Path $Script:ProjectPath -ChildPath build_tools
    $Script:BuildDependencies = Join-Path -Path $Script:ProjectPath -ChildPath "$Script:BuildTools\_build_dependencies_"
    $Script:Docs = Join-Path -Path $Script:ProjectPath -ChildPath Docs
    $Script:Source = Join-Path -Path $Script:ProjectPath -ChildPath src
    $Script:Build = Join-Path -Path $Script:ProjectPath -ChildPath build
    $Script:Dist = Join-Path -Path $Script:ProjectPath -ChildPath dist
    $Script:Destination = Join-Path -Path $Script:Dist -ChildPath $Script:ModuleName
    $Script:ModulePath = Join-Path -Path $Script:Destination -ChildPath "$Script:ModuleName.psm1"
    $Script:ReleasedModulePath = Join-Path -Path $Script:Build -ChildPath 'releasedModule'
    $Script:ManifestPath = Join-Path -Path $Script:Destination -ChildPath "$Script:ModuleName.psd1"
    $Script:ModuleDependencies = Join-Path -Path $Script:Destination -ChildPath 'Modules'
    $Script:ModuleTests = Join-Path -Path $Script:ProjectPath -ChildPath tests
    $Script:CommonTests = Join-Path -Path $Script:ProjectPath -Childpath build_tools\tests
    $Script:Tests = @(
        $Script:ModuleTests
        $Script:CommonTests
    )
    $Script:Imports = ('public', 'private', 'Scripts')
    $Script:Classes = (Get-ChildItem -Path "$Script:Source\Classes" -ErrorAction SilentlyContinue).Name
    $Script:minimumCoverage = 0.7
    $Script:NeedsPublished = $false
    $Script:IsPromotion = $false

    $Script:PatTokenCreds = GetPatTokenCreds -PatToken $PatToken
}

# Synopsis: Remove any existing build files
Task Clean {
    remove $Script:Build
    remove $Script:Dist
}

# Synopsis: Copy files and directories to the dist directory for testing/publishing
Task CopyDist {
    Write-Output "  Creating directory [$Script:Destination]"
    New-Item -Type Directory -Path $Script:Build -ErrorAction SilentlyContinue | Out-Null
    New-Item -Type Directory -Path $Script:Dist -ErrorAction SilentlyContinue | Out-Null
    New-Item -Type Directory -Path $Script:Destination -ErrorAction SilentlyContinue | Out-Null
    New-Item -Type Directory -Path $Script:Docs -ErrorAction SilentlyContinue | Out-Null

    Write-Output "  Files and directories to be copied from source [$Script:Source]"

    Get-ChildItem -Path $Script:Source -File |
        Where-Object -Property Name -NotMatch "$Script:ModuleName\.ps[md]1" |
        Copy-Item -Destination $Script:Destination -Force -PassThru |
        ForEach-Object {"   Creating file [{0}]" -f $_.fullname.replace($PSScriptRoot, '')}

    Get-ChildItem -Path $Script:Source -Directory |
        Copy-Item -Destination $Script:Destination -Recurse -Force -PassThru |
        ForEach-Object {"   Creating directory (recursive) [{0}]" -f $_.fullname.replace($PSScriptRoot, '')}
}

# Synopsis: Install the module dependencies (module.Depend.psd1) in the dist module directory
Task InstallModuleDependencies {
    Write-Output "  Installing module dependencies to [$Script:ModuleDependencies]"
    $invokePSDependParams = @{
        Path = "$Script:BuildTools\module.Depend.psd1"
        Target = $Script:ModuleDependencies
        Install = $true
        Force   = $true
        Credentials = @{
            PatTokenCreds = $Script:PatTokenCreds
        }
    }
    Invoke-PSDepend @invokePSDependParams -WarningAction SilentlyContinue -ErrorAction Stop
}

# Synopsis: Get the latest module release
Task GetReleasedModuleInfo {
    if (-not (Test-Path $Script:ReleasedModulePath)) {
        $null = New-Item -Path $Script:ReleasedModulePath -ItemType Directory
    }

    # This check is to allow pushing a bug fix directly into the master branch.
    # That way we do not end up with weird versioning issues. The bugfix in master
    # should be incremented based on the deployed master version, not any higher
    # prerelease versions.
    $preferRelease = -not $Prerelease -and -not $Script:IsPromotion
    $getPreviousReleaseParams = @{
        Name          = $Script:ModuleName
        Repository    = $Script:RepoName
        Path          = $Script:ReleasedModulePath
        PreferRelease = $preferRelease
        PatToken      = $PatToken
    }
    $release = GetPreviousRelease @getPreviousReleaseParams

    if ($release) {
        # Run in a job so we don't pollute the current session with released module version import
        $initScriptBlock = [scriptblock]::create(@"
Set-Location '$Script:ProjectPath'
function GetPublicFunctionInterfaces {$function:GetPublicFunctionInterfaces}
"@)
        $ScriptBlock = {
            $releasedModule = Import-Module -Name "$Using:ReleasedModulePath\$Using:ModuleName" -PassThru -Force -ErrorAction Stop

            $releasedModuleManifestPath = "$Using:ReleasedModulePath\$Using:ModuleName\$Using:ModuleName.psd1"
            $prereleaseValue = Get-ManifestValue -Path $releasedModuleManifestPath -PropertyName Prerelease
            $functionList = $releasedModule.ExportedFunctions.Values

            [PSCustomObject] @{
                Name = $releasedModule.Name
                Prerelease = $prereleaseValue -ne ''
                Version = $releasedModule.Version
            }
        }

        $Script:releasedModuleInfo = Start-Job -ScriptBlock $ScriptBlock -InitializationScript $initScriptBlock |
            Receive-Job -Wait -AutoRemoveJob

        Write-Output "  Found release [$($release.version)] for $Script:ModuleName"
    } else {
        Write-Warning (
            "No previous release found. If this is not a new module, follow the below steps:`n" +
            "    - Check your PAT token permissions and expiration`n" +
            "    - Check your internet connection`n" +
            "    - Check that the previous release artifact has not been delisted or deleted"
        )
    }
}

# Synopsis: Generate the module psm1 file
Task BuildPSM1 {
    [System.Text.StringBuilder]$StringBuilder = [System.Text.StringBuilder]::new()
    foreach ($class in $Script:Classes) {
        Write-Output "  Found $class"
        [void]$StringBuilder.AppendLine("using module 'Classes\$class'")
    }

    Push-Location -Path $Script:Destination
    try {
        $modules = (Get-ChildItem -Path "$Script:ModuleDependencies" -Recurse -Filter *.psd1).FullName
        foreach ($module in $modules) {
            $relativeModulePath = ($module | Resolve-Path -Relative).Substring(1)
            Write-Output "  Found $relativeModulePath"
            [void]$StringBuilder.AppendLine("")
            [void]$StringBuilder.AppendLine("Import-Module `"`$PSScriptRoot$relativeModulePath`" -Force")
        }
    } finally {
        Pop-Location
    }

    foreach ($folder in $Script:Imports)
    {
        [void]$StringBuilder.AppendLine("")
        [void]$StringBuilder.AppendLine("Write-Verbose `"Importing from [`$PSScriptRoot\$folder]`"")
        if (Test-Path "$Script:Source\$folder")
        {
            $fileList = Get-ChildItem "$Script:Source\$folder" -Filter '*.ps1'
            foreach ($file in $fileList)
            {
                $importName = "$folder\$($file.Name)"
                Write-Output "  Found $importName"
                [void]$StringBuilder.AppendLine( ". `"`$PSScriptRoot\$importName`"")
            }
        }
    }

    [void]$StringBuilder.AppendLine("")
    [void]$StringBuilder.AppendLine("`$publicFunctions = (Get-ChildItem -Path `"`$PSScriptRoot\public`" -Filter '*.ps1').BaseName")
    [void]$StringBuilder.AppendLine("")
    [void]$StringBuilder.AppendLine("Export-ModuleMember -Function `$publicFunctions")

    Write-Output "  Creating module [$Script:ModulePath]"
    Set-Content -Path $Script:ModulePath -Value $stringbuilder.ToString()
}

# Synopsis: Generate the module psd1 file
Task BuildPSD1 {
    Write-Output "  Updating [$Script:ManifestPath]"
    Copy-Item "$Script:Source\$Script:ModuleName.psd1" -Destination $Script:ManifestPath

    # Get dependency dlls, by relative path, and update RequiredAssemblies property
    Write-Output "  Detecting RequiredAssemblies"
    Push-Location $Script:Destination
    $dlls = Get-ChildItem "Modules" -Recurse -Filter *.dll | Resolve-Path -Relative
    Pop-Location
    if ($dlls) { Update-Metadata -Path $Script:ManifestPath -PropertyName RequiredAssemblies -Value $dlls }

    Write-Output "  Setting Module Functions"
    $moduleFunctions = Get-ChildItem -Path "$Script:Source\public" -Filter '*.ps1' | Select-Object -ExpandProperty BaseName
    Update-Metadata -Path $Script:ManifestPath -Property FunctionsToExport -Value $moduleFunctions

    Write-Output "  Setting ProjectUri"
    $ProjectUri = Invoke-Git config --get remote.origin.url
    if ($ProjectUri) { Update-Metadata $Script:ManifestPath -Property ProjectUri -Value $ProjectUri }

    Write-Output "  Setting Custom Formats"
    Push-Location -Path $Script:Destination
    $moduleFormats = Get-ChildItem -Path ".\Formats" -Filter '*.ps1xml' -ErrorAction SilentlyContinue | Resolve-Path -Relative
    if ($moduleFormats) { Update-Metadata -Path $Script:ManifestPath -Property FormatsToProcess -Value $moduleFormats }
    Pop-Location

    if ($Script:releasedModuleInfo) {
        Write-Output "  Detecting Module File Changes"
        $excludedFilesList = @(
            "$($Script:ModuleName).psd1",
            "$($Script:ModuleName)\Modules",
            ".xml",
            ".rels",
            ".psmdcp",
            ".nuspec",
            ".nupkg"
        )
        $GetModifiedFilesParams = @{
            ReferenceFolder = $Script:Destination
            DifferenceFolder = "$($Script:ReleasedModulePath)\$($Script:ModuleName)\*\"
            Exclude = $excludedFilesList
        }
        $changedFiles = GetModifiedFiles @GetModifiedFilesParams
        if ($changedFiles) {
            $changedFiles | ForEach-Object { "    $_" }
            $DetectedVersionIncrement = 'Patch'
        }

        Write-Output "  Detecting Function Interface Changes"
        # Run in a job so we don't pollute the current session with released module version import
        $initScriptBlock = [scriptblock]::create(@"
Set-Location '$Script:ProjectPath'
function GetPublicFunctionInterfaces {$function:GetPublicFunctionInterfaces}
"@)
        $scriptBlock = {
            # Detecting ReleasedModule Functions
            $releasedModuleManifestPath = "$Using:ReleasedModulePath\$Using:ModuleName\$Using:ModuleName.psd1"

            if (Test-Path -Path $releasedModuleManifestPath) {
                $oldFunctionList = (Import-Module -Name "$releasedModuleManifestPath" -Force -PassThru).ExportedFunctions.Values
                $oldFunctionInterfaces = GetPublicFunctionInterfaces -FunctionList $oldFunctionList

                # Detecting Current Module Functions
                $newFunctionList = (Import-Module -Name "$Using:ManifestPath" -Force -PassThru).ExportedFunctions.Values
                $newFunctionInterfaces = GetPublicFunctionInterfaces -FunctionList $newFunctionList

                # TestHelpers defines a new Pester assertion, so we need to make sure Pester is loaded
                if (-not (Invoke-PSDepend -Path "$Using:BuildTools\build.Depend.psd1" -Tags Test -Test -Quiet)) {
                    Invoke-PSDepend -Path "$Using:BuildTools\build.Depend.psd1" -Tags Test -Install -Force
                }
                Invoke-PSDepend -Path "$Using:BuildTools\build.Depend.psd1" -Tags Test -Import -Force
                Import-Module $Using:BuildTools\tests\TestHelpers.psm1 -DisableNameChecking
                Compare-PSObject -ReferenceObject $oldFunctionInterfaces -DifferenceObject $newFunctionInterfaces
            }
        }
        $functionInterfaceComparison = Start-Job -ScriptBlock $ScriptBlock -InitializationScript $initScriptBlock |
            Receive-Job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue -ErrorVariable err |
            Select-Object -Property * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName, PSSourceJobInstanceId

        foreach ($e in $err) {
            # Ignoring argument validator errors. These have only been encountered with dynamic parameter
            # functions that have mandatory arguments with validators.
            if ($e -and $e.exception.message -notlike 'Cannot validate argument on parameter*') {
                throw $e
            }
        }

        if ($err) {
            Write-Warning "Encountered Validator Errors (Not critical, but you may want to investigate)"
            $err | Select-Object -Unique | ForEach-Object {
                Write-Output $_
            }
        }

        if ($functionInterfaceComparison) {
            Write-Output "  Detecting New Features"
            if ($null -in $functionInterfaceComparison.ReferenceValue) {
                $DetectedVersionIncrement = 'Minor'
                $newFeatures = $functionInterfaceComparison | Where-Object { $null -eq $_.ReferenceValue }
                Write-Output "    Detected New Features"
                Write-Output "      $($newFeatures | Out-String)"
            }
        }

        if ($functionInterfaceComparison) {
            Write-Output "  Detecting Lost Features (breaking changes)"
            if ($null -in $functionInterfaceComparison.DifferenceValue) {
                $DetectedVersionIncrement = 'Major'
                Write-Output "    Detected Lost Features"
                $lostFeatures = $functionInterfaceComparison | Where-Object { $null -eq $_.DifferenceValue }
                Write-Output "      $($lostFeatures | Out-String)"
            }
            $mandatoryActivated = $functionInterfaceComparison | Where-Object {
                $_.Property -like '*.Mandatory' -and $_.ReferenceValue -eq $false -and $_.DifferenceValue -eq $true
            }
            if ($mandatoryActivated) {
                $DetectedVersionIncrement = 'Major'
                Write-Output "    Detected 'Mandatory' Property Changes"
                Write-Output "      $($mandatoryActivated | Out-String)"
            }
            $otherBreakingChange = $functionInterfaceComparison | Where-Object {
                ($_.Property -like '*.AllowEmptyString' -and $_.ReferenceValue -eq $true -and $_.DifferenceValue -eq $false) -or
                ($_.Property -like '*.AllowNull' -and $_.ReferenceValue -eq $true -and $_.DifferenceValue -eq $false) -or
                ($_.Property -like '*.ValueFromPipeline' -and $_.ReferenceValue -eq $true -and $_.DifferenceValue -eq $false) -or
                ($_.Property -like '*.ValueFromPipelineByPropertyName' -and $_.ReferenceValue -eq $true -and $_.DifferenceValue -eq $false) -or
                ($_.Property -like '*.ValueFromRemainingArguments' -and $_.ReferenceValue -eq $true -and $_.DifferenceValue -eq $false)
            }
            if ($otherBreakingChange) {
                $DetectedVersionIncrement = 'Major'
                Write-Output "    Detected Other Breaking Changes"
                Write-Output "      $($otherBreakingChange | Out-String)"
            }
        }
    }

    $version = [Version](Get-Metadata -Path $Script:ManifestPath -PropertyName ModuleVersion)

    # Don't bump major version if in pre-release
    if ($version -lt ([Version]"1.0.0")) {
        if ($DetectedVersionIncrement -eq 'Major') {
            $DetectedVersionIncrement = 'Minor'
        }
    }

    $releasedVersion = $Script:releasedModuleInfo.Version
    $releaseIsPrerelease = $Script:releasedModuleInfo.Prerelease

    if (-not $VersionIncrement) {
        $VersionIncrement = $DetectedVersionIncrement
    } else {
        if ($DetectedVersionIncrement) {
            Write-Output "  Manual version increment [$VersionIncrement] requested, ignoring detected version increment [$DetectedVersionIncrement]"
        } else {
            Write-Output "  Manual version increment [$VersionIncrement] requested"
        }
    }

    if ($version -gt $releasedVersion) {
        $Script:NeedsPublished = $true
        $relativeManifestPath = "$Script:Source\$Script:ModuleName.psd1" | Resolve-Path -Relative
        Write-Output "  Detected manual version increment, using version from $($relativeManifestPath): [$version]"
        $Script:NeedsPublished = $true
    } elseif (-not $Prerelease -and $releaseIsPrerelease -and -not $VersionIncrement) {
        $version = $releasedVersion
        Write-Output "  Promoting [$version] to release!"
        $Script:NeedsPublished = $true
    } elseif ($VersionIncrement) {
        $version = [Version](Step-Version -Version $releasedVersion -By $VersionIncrement)
        Write-Output "  Stepping module from released version [$releasedVersion] to new version [$version] by [$VersionIncrement] revision"
        $Script:NeedsPublished = $true
    } else {
        Write-Output "No changes detected, using version from released version [$releasedVersion]"
        $version = $releasedVersion
    }

    Update-Metadata -Path $Script:ManifestPath -PropertyName 'ModuleVersion' -Value $version

    if ($Prerelease) {
        Update-Metadata -Path $Script:ManifestPath -PropertyName Prerelease -Value 'prerelease'
    }
}

# Synopsis: Run the full build and test suite
Task Test Build, Pester, CodeHealth, CheckCodeCoverage

# Synopsis: Execute Pester tests
Task Pester Build, {
    Write-Output "  Setting up test dependencies"
    Remove-Module Pester -Force -ErrorAction SilentlyContinue

    if (-not (Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags Test -Test -Quiet)) {
        Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags Test -Install -Force
    }
    Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags Test -Import -Force

    # # We are importing this here, instead of in our tests for two reasons
    # #   1. Pester has a bug where mocks leak into other imported modules when imported into the same session
    # #   2. This way we also do not need to import these helpers in each test script
    Import-Module -Name $Script:BuildTools\tests\TestHelpers.psm1 -Force -DisableNameChecking

    Get-Module -All -Name $Script:ModuleName | Remove-Module -Force -ErrorAction SilentlyContinue

    Write-Output "  Setting up test configuration"
    $configuration                           = New-PesterConfiguration
    $configuration.Run.Path                  = @($Script:Tests)
    $configuration.Output.Verbosity          = 'Normal'
    $configuration.Run.PassThru              = $true
    $configuration.TestResult.Enabled        = $true
    $configuration.TestResult.OutputPath     = "$Script:Build\testResults.xml"
    $configuration.Should.ErrorAction        = 'SilentlyContinue'

    if ($Script:Coverage) {
        $configuration.CodeCoverage.Enabled               = $true
        $configuration.CodeCoverage.Path                  = "$Script:Destination\Public\*.ps1", "$Script:Destination\Private\*.ps1"
        $configuration.CodeCoverage.OutputFormat          = 'JaCoCo'
        $configuration.CodeCoverage.OutputPath            = "$Script:Build\coverage.xml"
        $configuration.CodeCoverage.CoveragePercentTarget = $Script:minimumCoverage
    }
    Write-Output "  Starting Pester tests"
    $pesterResults = Invoke-Pester -Configuration $configuration -Verbose:$VerbosePreference

    Write-Output "  Tests completed, exporting Pester 5 results"
    $pesterResults | Export-Clixml -Path "$Script:Build\pester5Results.xml" -Encoding UTF8 -Depth 5

    Write-Output "  Tests completed, exporting Pester 4 (converted) results"
    $pesterResults | ConvertTo-Pester4Result | Export-Clixml -Path "$Script:Build\pester4Results.xml" -Encoding UTF8 -Depth 5

    Remove-Module -Name Pester -Force -ErrorAction SilentlyContinue

    assert ($pesterResults) "There was a terminal error when executing the Pester tests."
}

# Synopsis: Execute PSCodeHealth checks
Task CodeHealth -If {Get-Item -Path "$Script:Build\pester4Results.xml"} {
    # Run CodeHealth in a job so we don't pollute the current session with Pester 4 import
    $scriptBlock = {
        Write-Output "  Setting up CodeHealth dependencies"

        if (-not (Invoke-PSDepend -Path "$Using:BuildTools\build.Depend.psd1" -Tags CodeHealth -Test -Quiet)) {
            Invoke-PSDepend -Path "$Using:BuildTools\build.Depend.psd1" -Tags CodeHealth -Install -Force
        }
        Invoke-PSDepend -Path "$Using:BuildTools\build.Depend.psd1" -Tags CodeHealth -Import -Force

        $testResults = Import-Clixml -Path "$Using:Build\pester4Results.xml"

        # Get module dependency scripts for -Exclude
        $excludeScripts = (Get-ChildItem -Path $Using:ModuleDependencies -Recurse -ErrorAction SilentlyContinue).Name

        Write-Output "  Running PSCodeHealth, this may take some time..."
        $InvokePSCodeHealthParams = @{
            Path               = $Using:Destination
            TestsResult        = $testResults
            Recurse            = $true
            HtmlReportPath     = "$Using:Build\codeHealthResults.html"
            CustomSettingsPath = "$Using:BuildTools\PSCodeHealthSettings.json"
            Passthru           = $true
            ErrorAction        = 'SilentlyContinue'
        }
        if ($excludeScripts) { $InvokePSCodeHealthParams['Exclude'] = $excludeScripts }

        Write-Output "    PSCodeHealth params:`n$($InvokePSCodeHealthParams | Out-String)"

        $results = Invoke-PSCodeHealth @InvokePSCodeHealthParams -Verbose:$Using:VerbosePreference

        if ($results) {
            $results | Export-Clixml -Path "$Using:Build\codeHealthResults.xml" -Depth 5
            $pass = Test-PSCodeHealthCompliance -HealthReport $results -CustomSettingsPath "$Using:BuildTools\PSCodeHealthSettings.json"
            if ($codeHealthWarnings = $pass | ForEach-Object { if ($_.Result -eq 'Warning') {$_} }) {
                Write-Output "  Code health warnings:"
                $codeHealthWarnings | Format-Table  # Formatting for output from the ps job
            }

            if ($codeHealthFailures = $pass | ForEach-Object { if ($_.Result -eq 'Fail') {$_} }) {
                Write-Output "  Code health failures:"
                $codeHealthFailures | Format-Table  # Formatting for output from the ps job
            }
        }

        $functionHealthRecords = $results.FunctionHealthRecords
        $PSScriptAnalyzerFindings = $functionHealthRecords | ForEach-Object {
            $functionHealthRecord = $_
            $findings = $functionHealthRecord.ScriptAnalyzerResultDetails | Where-Object { $_.Severity -match 'Warning|Error' }
            if ($findings) {
                $scriptName = "$($functionHealthRecord.FunctionName).ps1"
                $findings | Add-Member -MemberType NoteProperty -Name ScriptName -Value $scriptName -Force -PassThru
            }
        }

        if ($PSScriptAnalyzerFindings) {
            Write-Output "  PSScriptAnalyzer findings:"
            $PSScriptAnalyzerFindings | Format-Table  # Formatting for output from the ps job
        }

        if ($results -and -not $codeHealthFailures) {
            Write-Output "  CodeHealth checks passed!"
        } else {
            throw 'PSCodeHealth tests failed!'
        }
    }
    Start-Job -Name CodeHealth -Init ([ScriptBlock]::Create("Set-Location '$Script:ProjectPath'")) -ScriptBlock $scriptBlock | Receive-Job -Wait -AutoRemoveJob
}

# Synopsis: Validate the Pester code coverage against the minimum coverage
Task CheckCodeCoverage -If ($Coverage) {
    [xml]$test = Get-Content "$Script:Build\coverage.xml"
    $lineCoverage = $test.report.counter | Where-Object { $_.type -eq 'LINE' }
    $totalLines = [int]$lineCoverage.missed + [int]$lineCoverage.covered
    $coveragePercentage = $lineCoverage.covered / $totalLines

    if ($ValidateCoverage) {
        assert ($coveragePercentage -ge $minimumCoverage) "Code coverage policy failed with $($coveragePercentage.tostring("P")) ($($lineCoverage.covered)/$totalLines lines)."

        Write-Output "  Code coverage policy passed with $($coveragePercentage.tostring("P")) ($($lineCoverage.covered)/$totalLines lines)."
    }
}

# Synopsis: Verifies if the branch that triggered this build is a valid stage (protected prerelease branch)
Task VerifyTriggeringBranch -If (-not $prerelease) {
    $currentCommit = git rev-parse HEAD
    $matchingPullRequest = GetAzurePullRequest -CommitHash $currentCommit -PatToken $PatToken
    $triggeringBranchName = $matchingPullRequest.sourceRefName -replace 'refs/heads/'
    if ($triggeringBranchName -eq "$($Script:ModuleName)_prerelease") {
        $Script:IsPromotion = $true
    }
    if ($triggeringBranchName) { Write-Output "  Triggering branch name: $triggeringBranchName"}
}

# Synopsis: Generate nupkg file from build
Task PackageModule Build, {
    if ($Script:NeedsPublished) {
        $nuspecPath = "$Script:Dist\$Script:ModuleName.nuspec"
        . $Script:BuildTools\NewNuspecFile.ps1 -ManifestPath $Script:ManifestPath -DestinationFolder $Script:Dist
        nuget pack $nuspecPath -OutputDirectory $Script:Dist -nopackageanalysis

        Write-Host "##vso[task.setvariable variable=needsPublished;isOutput=true]True"

        $version = (Select-Xml -XPath "/package/metadata/version" -Path $nuspecPath).Node.InnerText
        $name = (Select-Xml -XPath "/package/metadata/id" -Path $nuspecPath).Node.InnerText
        $releaseName = "$name-$version"
        $commitHash = git rev-parse --short HEAD
        $buildName = "$($releaseName)_$($commitHash)"

        Write-Output "ModuleVersion: $releaseName"
        Write-Output "CommitHash: $commitHash"
        Write-Output "Setting BuildName: [$buildName]"
        Write-Host "##vso[build.updatebuildnumber]$buildName"
    } else {
        Write-Output "  Build does not need to be published"
    }
}

# Synopsis: Create Pester test scripts for existing functions that are missing Pester tests
Task GenerateTestFiles {
    $functionTypes = 'Public', 'Private'

    $functionTypes | ForEach-Object {
        $functionType = $_
        $private = $functionType -eq 'Private'

        # Get module functions
        $functionScripts = Get-ChildItem -Path "$Script:Source\$functionType" -Filter '*.ps1' -Recurse
        $functionList = $functionScripts.Name -replace '.ps1'

        $testScripts = Get-ChildItem -Path "$Script:ModuleTests\$functionType" -Filter '*.ps1' -Recurse
        $testList = $testScripts.Name -replace '.Tests.ps1'

        foreach ($function in $functionList) {
            if ($function -notin $testList) {
                $invokePlasterParams = @{
                    TemplatePath    = "$Script:BuildTools\templates\FunctionTest"
                    ModuleName      = $Script:ModuleName
                    FunctionName    = $function
                    FunctionType    = $functionType
                    DestinationPath = $Script:ModuleTests
                    NoLogo          = $true
                }
                Invoke-Plaster @invokePlasterParams
            }
        }
    }
}

# Synopsis: Create a new module function script
Task NewFunction {
    $invokePlasterParams = @{
        TemplatePath    = "$Script:BuildTools\templates\ModuleFunction"
        ModuleName      = $Script:ModuleName
        DestinationPath = $Script:Source
        NoLogo          = $true
    }
    Invoke-Plaster @invokePlasterParams
}, GenerateTestFiles
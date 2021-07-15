# Adapted from https://github.com/mcbobke/PlasterModuleTemplate
Param(
    [string]$VersionIncrement,
    [switch]$Coverage
)

# Runs full Build and Test process
Task Default Build, Test

# Builds the [Output] directory and prepares the module for testing and publishing
Task Build Clean, CopyOutput, GetReleasedModuleInfo, BuildPSM1, BuildPSD1

Enter-Build {
    if (!(Get-Item 'Env:\BH*')) {
        Set-BuildEnvironment
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    function GetPreviousRelease {
        Param (
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [string]$Repository,

            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter()]
            [switch]$Prerelease,

            [Parameter()]
            [string]$PatToken
        )

        try {
            $SaveModuleParams = @{
                Name            = $Name
                Path            = $Path
                Repository      = 'PSGallery'
                AllowPrerelease = $Prerelease
                Force           = $true
                ErrorAction     = 'Stop'
            }

            Save-Module @SaveModuleParams
        } catch {
            if ($_ -match "No match was found for the specified search criteria") {
                Write-Output "  No match was found for the specified search criteria"
            }
            else {
                $_
            }
        }
    }

    function GetPublicFunctionInterfaces {
        Param (
            [System.Management.Automation.FunctionInfo[]]
            $FunctionList
        )

        $functionInterfaces = New-Object -TypeName System.Collections.ArrayList

        foreach ($function in $FunctionList) {
            foreach ($parameter in $function.Parameters.Keys) {
                Write-Verbose "$($function.Name)"
                Write-Verbose "$($function.Parameters[$parameter].Name)"
                $toAdd = "{0}:{1}" -f $function.Name, $function.Parameters[$parameter].Name
                $functionInterfaces.Add($toAdd)

                foreach ($alias in $function.Parameters[$parameter].Aliases) {
                    Write-Verbose "$($function.Name)"
                    Write-Verbose "$($alias)"
                    $toAdd = "{0}:{1}" -f $function.Name, $alias
                    $functionInterfaces.Add($toAdd)
                }
            }
        }

        return $functionInterfaces
    }

    function GetPSRepositoryNameBySourceLocation {
        param (
            [string]$SourceLocation
        )
        (Get-PSRepository | Where-Object { $_.SourceLocation -eq $SourceLocation }).Name
    }

    $Script:ModuleName = $Env:BHProjectName
    $Script:BuildTools = Join-Path -Path $Env:BHProjectPath -ChildPath build_tools
    $Script:BuildDependencies = Join-Path -Path $Env:BHProjectPath -ChildPath "$Script:BuildTools\_build_dependencies_"
    $Script:Docs = Join-Path -Path $Env:BHProjectPath -ChildPath Docs
    $Script:Source = Join-Path -Path $Env:BHProjectPath -ChildPath src
    $Script:Build = Join-Path -Path $Env:BHProjectPath -ChildPath build
    $Script:Dist = Join-Path -Path $Env:BHProjectPath -ChildPath dist
    $Script:Destination = Join-Path -Path $Script:Dist -ChildPath $Script:ModuleName
    $Script:ModulePath = Join-Path -Path $Script:Destination -ChildPath "$Script:ModuleName.psm1"
    $Script:ReleasedModulePath = Join-Path -Path $Script:Build -ChildPath 'releasedModule'
    $Script:ManifestPath = Join-Path -Path $Script:Destination -ChildPath "$Script:ModuleName.psd1"
    $Script:ModuleDependencies = Join-Path -Path $Script:Destination -ChildPath 'Modules'
    $Script:Tests = @(
        Join-Path -Path $Env:BHProjectPath -ChildPath tests
        Join-Path -Path $Env:BHProjectPath -Childpath build_tools\tests
    )
    $Script:Imports = ('public', 'private')
    # $Script:Classes = (Get-ChildItem -Path "$Script:Source\Classes").Name
    $Script:minimumCoverage = 0.7
    # $Script:publishToRepo = GetPSRepositoryNameBySourceLocation -SourceLocation $PackageSourceUrl
    $Script:NeedsPublished = $false
    if (-not $Script:publishToRepo) {
        $Script:publishToRepo = "AzDoPSRepo_$([guid]::NewGuid())"
        $Script:removeRepo = $true
    }

    function GetModifiedFiles {
        param (
            [string]$ReferenceFolder,
            [string]$DifferenceFolder,
            [string[]]$Exclude
        )
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
}

Exit-Build {
}

Task Clean {
    Remove-Item -Path $Script:Build -Recurse -Force -ErrorAction Ignore | Out-Null
    Remove-Item -Path $Script:Dist -Recurse -Force -ErrorAction Ignore | Out-Null
    Remove-Item -Path $Script:Docs -Recurse -Force -ErrorAction Ignore | Out-Null
}

Task CopyOutput {
    Write-Output "  Creating directory [$Script:Destination]"
    New-Item -Type Directory -Path $Script:Build -ErrorAction Ignore | Out-Null
    New-Item -Type Directory -Path $Script:Dist -ErrorAction Ignore | Out-Null
    New-Item -Type Directory -Path $Script:Destination -ErrorAction Ignore | Out-Null
    New-Item -Type Directory -Path $Script:Docs -ErrorAction Ignore | Out-Null

    Write-Output "  Files and directories to be copied from source [$Script:Source]"

    Get-ChildItem -Path $Script:Source -File |
        Where-Object -Property Name -NotMatch "$Script:ModuleName\.ps[md]1" |
        Copy-Item -Destination $Script:Destination -Force -PassThru |
        ForEach-Object {"   Creating file [{0}]" -f $_.fullname.replace($PSScriptRoot, '')}

    Get-ChildItem -Path $Script:Source -Directory |
        Copy-Item -Destination $Script:Destination -Recurse -Force -PassThru |
        ForEach-Object {"   Creating directory (recursive) [{0}]" -f $_.fullname.replace($PSScriptRoot, '')}
}

Task GetReleasedModuleInfo RegisterPSRepository, {
    if (!(Test-Path $Script:ReleasedModulePath)) {
        $null = New-Item -Path $Script:ReleasedModulePath -ItemType Directory
    }

    GetPreviousRelease -Name $Script:ModuleName -Repository $Script:publishToRepo -Path $Script:ReleasedModulePath -Prerelease -PatToken $PatToken

    $initScriptBlock = [scriptblock]::create(@"
function GetPublicFunctionInterfaces {$function:GetPublicFunctionInterfaces}
"@)
    $ScriptBlock = {
        Set-Location -Path (Get-BuildVariable).ProjectPath

        try {
            $releasedModule = Import-Module -Name "$Using:ReleasedModulePath\$Using:ModuleName" -PassThru -ErrorAction Stop
            Write-Output "  Found previous release: [$($releasedModule.Name)-$($releasedModule.Version)]"
            $releasedModuleManifestPath = "$Using:ReleasedModulePath\$Using:ModuleName\*\$Using:ModuleName.psd1"
            $prereleaseValue = Get-ManifestValue -Path $releasedModuleManifestPath -PropertyName Prerelease
        }
        catch {
            $_
        }

        if (($releasedModule -ne $null) -and ($releasedModule.GetType() -eq [System.Management.Automation.ErrorRecord])) {
            Write-Error $releasedModule
            return
        }

        if ($releasedModule -eq $null) {
            $moduleInfo = [PSCustomObject] @{
                Version = [Version]::New(0, 0, 1)
                FunctionInterfaces = New-Object -TypeName System.Collections.ArrayList
            }
        } else {
            $moduleInfo = [PSCustomObject] @{
                Prerelease = if ($prereleaseValue) { "-$prereleaseValue" } else { $null }
                Version = $releasedModule.Version
                FunctionInterfaces = GetPublicFunctionInterfaces -FunctionList $releasedModule.ExportedFunctions.Values
            }
        }

        $moduleInfo | Export-Clixml -Path "$Using:Build\released-module-info.xml" -Encoding UTF8
    }

    Start-Job -ScriptBlock $ScriptBlock -InitializationScript $initScriptBlock | Receive-Job -Wait -AutoRemoveJob
}

Task BuildPSM1 {
    [System.Text.StringBuilder]$StringBuilder = [System.Text.StringBuilder]::new()
    foreach ($class in $Script:Classes) {
        Write-Output "  Found $class"
        [void]$StringBuilder.AppendLine("using module 'Classes\$class'")
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

Task BuildPSD1 {
    Write-Output "  Updating [$Script:ManifestPath]"
    Copy-Item "$Script:Source\$Script:ModuleName.psd1" -Destination $Script:ManifestPath

    Write-Output "  Setting Module Functions"
    $moduleFunctions = Get-ChildItem -Path "$Script:Source\public" -Filter '*.ps1' | Select-Object -ExpandProperty BaseName
    Set-ModuleFunctions -Name $Script:ManifestPath -FunctionsToExport $moduleFunctions
    Set-ModuleAliases -Name $Script:ManifestPath

    Write-Output "  Setting ProjectUri"
    $ProjectUri = Invoke-Git config --get remote.origin.url
    if ($ProjectUri) { Update-Metadata $Script:ManifestPath -Property ProjectUri -Value $ProjectUri }

    Write-Output "  Setting Custom Formats"
    Set-ModuleFormat $Script:ManifestPath -FormatsRelativePath './Formats'

    Write-Output "  Detecting ReleasedModule Functions"
    if (Test-Path -Path "$Script:Build\released-module-info.xml") {
        $releasedModuleInfo = Import-Clixml -Path "$Script:Build\released-module-info.xml"
        $oldFunctionInterfaces = $releasedModuleInfo.FunctionInterfaces
    } else {
        $oldFunctionInterfaces = @()
    }

    Write-Output "  Detecting Current Module Functions"
    $functionList = (Import-Module -Name "$Script:ManifestPath" -PassThru).ExportedFunctions.Values
    $newFunctionInterfaces = GetPublicFunctionInterfaces -FunctionList $functionList

    Write-Output "  Detecting new features"
    foreach ($interface in $newFunctionInterfaces) {
        if ($interface -notin $oldFunctionInterfaces) {
            $DetectedVersionIncrement = 'Minor'
            Write-Output "      $interface"
        }
    }
    Write-Output "  Detecting lost features (breaking changes)"
    foreach ($interface in $oldFunctionInterfaces) {
        if ($interface -notin $newFunctionInterfaces) {
            $DetectedVersionIncrement = 'Major'
            Write-Output "      $interface"
        }
    }

    $version = [Version](Get-Metadata -Path $Script:ManifestPath -PropertyName ModuleVersion)

    # Don't bump major version if in pre-release
    if ($version -lt ([Version]"1.0.0") -or $Prerelease) {
        if ($DetectedVersionIncrement -eq 'Major') {
            $DetectedVersionIncrement = 'Minor'
        }
        else {
            $DetectedVersionIncrement = 'Patch'
        }
    }

    $releasedVersion = $releasedModuleInfo.Version

    Write-Output "  Detecting other file changes"
    $GetModifiedFilesParams = @{
        ReferenceFolder = $Script:Destination
        DifferenceFolder = "$($Script:ReleasedModulePath)\$($Script:ModuleName)\*\"
        Exclude = "$($Script:ModuleName).psd1", 'Modules'
    }
    $changedFiles = GetModifiedFiles @GetModifiedFilesParams
    $changedFiles | ForEach-Object { "    $_" }

    if (-not $VersionIncrement) {
        $VersionIncrement = $DetectedVersionIncrement
    } else {
        Write-Output "  Manual version increment [$VersionIncrement] requested, ignoring detected version increment [$DetectedVersionIncrement]"
    }

    if ($version -le $releasedVersion -and $changedFiles) {
        $version = [Version](Step-Version -Version $releasedVersion -By $VersionIncrement)
        if ($Prerelease) {
            $versionString = "$version-prerelease"
        } else {
            $versionString = "$version"
        }
        Write-Output "  Stepping module from released version [$releasedVersion$($releasedModuleInfo.Prerelease)] to new version [$versionString] by [$VersionIncrement]"
        $Script:NeedsPublished = $true
    } elseif ($version -lt $releasedVersion) {
        $version = $releasedVersion
        Write-Output "  Using released version: [$version]"
    } else {
        Write-Output "  Using version from $Script:ModuleName.psd1: [$version]"
    }

    Update-Metadata -Path $Script:ManifestPath -PropertyName 'ModuleVersion' -Value $version
    if ($Prerelease) {
        Update-Metadata -Path $Script:ManifestPath -PropertyName Prerelease -Value 'prerelease'
    } elseif ($releasedVersion.Prerelease -ne '') {
        $Script:NeedsPublished = $true
    }
}

Task Test Pester, CodeHealth, CheckCodeCoverage

Task Pester Build, {
    Remove-Module -Name Pester -Force -ErrorAction Ignore

    if (-not (Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags Test -Test -Quiet)) {
        Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags Test -Install -Force
    }
    Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags Test -Import -Force

    Import-Module -Name $Script:ManifestPath -Force

    Get-Module -All -Name $Script:ModuleName | Remove-Module -Force -ErrorAction 'Ignore'

    $configuration                           = [PesterConfiguration]::Default
    $configuration.Run.Path                  = $Script:Tests
    $configuration.Output.Verbosity          = 'Normal'
    $configuration.Run.PassThru              = $true
    $configuration.TestResult.Enabled        = $true
    $configuration.TestResult.OutputPath     = "$Script:Build\testResults.xml"
    $configuration.Should.ErrorAction        = 'SilentlyContinue'

    if ($Coverage) {
        $configuration.CodeCoverage.Enabled      = $true
        $configuration.CodeCoverage.Path         = "$Script:Destination\**\*.ps1"
        $configuration.CodeCoverage.OutputFormat = 'NUnitXML'
        $configuration.CodeCoverage.OutputPath   = "$Script:Build\coverage.xml"
    }

    $pesterResults = Invoke-Pester -Configuration $configuration -Verbose:$VerbosePreference
    $pesterResults | Export-Clixml -Path "$Script:Build\pester5Results.xml" -Encoding UTF8
    $pesterResults | ConvertTo-Pester4Result | Export-Clixml -Path "$Script:Build\pester4Results.xml" -Encoding UTF8

    Remove-Module -Name Pester -Force -ErrorAction Ignore

    assert ($pesterResults) "There was a terminal error when executing the Pester tests."
}

Task CodeHealth Build, Pester, {
    Remove-Module -Name Pester -Force -ErrorAction Ignore

    if (-not (Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags CodeHealth -Test -Quiet)) {
        Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags CodeHealth -Install -Force
    }
    Invoke-PSDepend -Path "$Script:BuildTools\build.Depend.psd1" -Tags CodeHealth -Import -Force

    $testResults = Import-Clixml -Path "$Script:Build\pester4Results.xml"

    # Get module dependency scripts for -Exclude
    $excludeScripts = (Get-ChildItem -Path $Script:ModuleDependencies -Recurse -ErrorAction Ignore).Name

    $InvokePSCodeHealthParams = @{
        Path               = $Script:Destination
        TestsResult        = $testResults
        Recurse            = $true
        # Exclude            = $excludeScripts
        HtmlReportPath     = "$Script:Build\codeHealthResults.html"
        CustomSettingsPath = "$Script:BuildTools\PSCodeHealthSettings.json"
        Passthru           = $true
        WarningAction      = 'Ignore'
        ErrorAction        = 'Ignore'
    }
    if ($excludeScripts) { $InvokePSCodeHealthParams['Exclude'] = $excludeScripts }
    $results = Invoke-PSCodeHealth @InvokePSCodeHealthParams
    if ($results) {
        $results | Export-Clixml -Path "$Script:Build\codeHealthResults.xml"
        $pass = Test-PSCodeHealthCompliance -HealthReport $results -CustomSettingsPath "$Script:BuildTools\PSCodeHealthSettings.json"
        if ($codeHealthWarnings = $pass | ForEach-Object { if ($_.Result -eq 'Warning') {$_} }) {
            Write-Output "  Code health warnings:"
            $codeHealthWarnings
        }

        if ($codeHealthFailures = $pass | ForEach-Object { if ($_.Result -eq 'Fail') {$_} }) {
            Write-Output "  Code health failures:"
            $codeHealthFailures
        }
    }

    Remove-Module -Name Pester, PSCodeHealth -Force -ErrorAction Ignore

    assert (-not $codeHealthFailures) 'PSCodeHealth tests failed!'
}

Task CheckCodeCoverage -If ($Coverage) {
    [xml]$test = Get-Content "$Script:Build\coverage.xml"
    $lineCoverage = $test.report.counter | Where-Object { $_.type -eq 'LINE' }
    $totalLines = [int]$lineCoverage.missed + [int]$lineCoverage.covered
    $coveragePercentage = $lineCoverage.covered / $totalLines

    assert ($coveragePercentage -ge $minimumCoverage) "Code coverage policy failed with $($coveragePercentage.tostring("P")) ($($lineCoverage.covered)/$totalLines lines)."

    Write-Output "  Code coverage policy passed with $($coveragePercentage.tostring("P")) ($($lineCoverage.covered)/$totalLines lines)."
}

Task RegisterPSRepository {

}

Task PackageModule Build, {
    if ($Script:NeedsPublished) {
        . $Script:BuildTools\NewNuspecFile.ps1 -ManifestPath $Script:ManifestPath -DestinationFolder $Script:Dist
        nuget pack "$Script:Dist\$Script:ModuleName.nuspec" -OutputDirectory $Script:Dist -nopackageanalysis
    } else {
        Write-Output "  Build does not need to be published"
    }
}

Task Import Build, {
    Write-Output "  Import module from path [$Script:ManifestPath]"
    Import-Module -Name $Script:ManifestPath -Force -Verbose:$VerbosePreference
}
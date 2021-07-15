[CmdletBinding()]
Param (
    [Parameter()]
    $Task = 'Default',

    [Parameter()]
    [ValidateSet('Patch', 'Minor', 'Major')]
    $VersionIncrement,

    [Parameter()]
    [switch]$Coverage,

    # [Parameter()]
    # [switch]$PreRelease,

    [Parameter()]
    [switch]$Help
)

DynamicParam {
    # Adapted from https://github.com/nightroman/Invoke-Build/blob/master/Invoke-Build.ArgumentCompleters.ps1

    Register-ArgumentCompleter -CommandName build.ps1 -ParameterName Task -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $boundParameters)

        (Invoke-Build -Task ?? -File "$PSScriptRoot\build_tools\module.build.ps1").get_Keys() -like "$wordToComplete*" | .{process{
            New-Object System.Management.Automation.CompletionResult $_, $_, 'ParameterValue', $_
        }}
    }

    Set-BuildEnvironment -Force
}

begin {
    $buildFile = "$PSScriptRoot\build_tools\module.build.ps1"
}

process {
    if ($Help) {
        Invoke-Build -File $buildFile -Task ?
    } else {
        Write-Output "Starting build of PSObjectTools"

        $PSDependVersion = '0.3.8'
        if (-not (Get-InstalledModule -Name 'PSDepend' -RequiredVersion $PSDependVersion -ErrorAction 'SilentlyContinue')) {
            Install-Module -Name 'PSDepend' -Repository PSGallery -RequiredVersion $PSDependVersion -Force -Scope 'CurrentUser'
        }
        Import-Module -Name 'PSDepend' -RequiredVersion $PSDependVersion

        if (!(Get-PackageProvider -Name 'NuGet')) {
            Write-Output "Installing Nuget package provider..."
            Install-PackageProvider -Name 'NuGet' -Force -Confirm:$false | Out-Null
        }

        Write-Output "Install/Import Build-Dependent Modules"
        Invoke-PSDepend -Path "$PSScriptRoot\build_tools\build.Depend.psd1" -Tags Build -Install -Import -Force -Verbose:$VerbosePreference

        $InvokeBuildParams = @{
            File             = $buildFile
            Task             = $Task
            VersionIncrement = $VersionIncrement
            Coverage         = $Coverage
            # PackageSourceUrl = $PackageSourceUrl
            # PatToken         = $PatToken
            # PreRelease       = $PreRelease
            Verbose          = $VerbosePreference
        }
        Invoke-Build @InvokeBuildParams
    }
}

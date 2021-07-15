
# Adapted from @juneb_get_help (https://raw.githubusercontent.com/juneb/PesterTDD/master/Module.Help.Tests.ps1)

Describe 'Test Help' {

    ## When testing help, remember that help is cached at the beginning of each session.
    ## To test, restart session.

    # Setting up test cases
    $outputDir = Join-Path -Path $ENV:BHProjectPath -ChildPath 'Output'
    $outputModDir = Join-Path -Path $outputDir -ChildPath $env:BHProjectName
    $outputManifestPath = Join-Path -Path $outputModDir -Child "$($env:BHProjectName).psd1"

    # Remove all versions of the module from the session. Pester can't handle multiple versions.
    Get-Module $env:BHProjectName | Remove-Module -Force
    Import-Module -Name $outputManifestPath -ErrorAction Stop
    $commands = Get-Command -Module (Get-Module $env:BHProjectName) -CommandType Cmdlet, Function, Workflow  # Not alias
    $helpHash = @{}
    $documentationTestCases = $commands | ForEach-Object {
        $commandName = $_.Name
        # The module-qualified command fails on Microsoft.PowerShell.Archive cmdlets
        $helpHash["$commandName"] = Get-Help $commandName -ErrorAction SilentlyContinue
        @{ CommandName = $commandName; Help = $helpHash[$commandName] }
    }

    $commonParameters = 'Debug', 'ErrorAction', 'ErrorVariable', 'InformationAction', 'InformationVariable', 'OutBuffer',
                'OutVariable', 'PipelineVariable', 'Verbose', 'WarningAction', 'WarningVariable', 'Confirm', 'Whatif'

    $commandParametersTestCases = $commands | ForEach-Object {
        $commandName = $_.Name

        $parameters = $_.ParameterSets.Parameters | Sort-Object -Property Name -Unique | Where-Object { $_.Name -notin $commonParameters }

        $parameters | ForEach-Object {
            $parameterName = $_.Name
            @{
                CommandName       = $commandName
                ParameterName     = $parameterName
                ParameterHelp     = $helpHash[$commandName].parameters.parameter | Where-Object { $_.Name -eq $parameterName }
                Parameter         = $_
            }
        }
    }

    $helpParametersTestCases = $commands | ForEach-Object {
        $commandName = $_.Name

        $parameters = $_.ParameterSets.Parameters | Sort-Object -Property Name -Unique | Where-Object { $_.Name -notin $commonParameters }
        $parameterNames = $parameters.Name

        ## Without the filter, WhatIf and Confirm parameters are still flagged in "finds help parameter in code" test
        $helpParameters = $helpHash[$commandName].Parameters.Parameter | Where-Object { $_.Name -notin $commonParameters } | Select-Object -Unique

        $helpParameters | ForEach-Object {
            $helpParameterName = $_.Name
            @{
                CommandName       = $commandName
                HelpParameterName = $helpParameterName
                HelpParameter     = $_
                AllParameterNames = $parameterNames
            }
        }
    }

    $linksTestCases = $commands | ForEach-Object {
        $commandName = $_.Name
        $commandLinks = $helpHash[$commandName].relatedLinks.navigationLink.uri

        if ($commandLinks) {
            $commandLinks | ForEach-Object {
                @{ CommandName = $commandName; Link = $_ }
            }
        }
    }

    Context 'Help Documentation' {
        # If help is not found, synopsis in auto-generated help is the syntax diagram
        It 'Should not be auto-generated for [<CommandName>]' -TestCases $documentationTestCases {
            $help.Synopsis | Should -Not -BeLike '*`[`<CommonParameters`>`]*'
        }

        # Should be a description for every function
        It "Should have description for [<CommandName>]" -TestCases $documentationTestCases {
            $help.Description | Should -Not -BeNullOrEmpty
        }

        # Should be at least one example
        It "Should have example code from [<CommandName>]" -TestCases $documentationTestCases {
            ($help.Examples.Example | Select-Object -First 1).Code | Should -Not -BeNullOrEmpty
        }

        # Should be at least one example description
        It "Should have example help from [<CommandName>]" -TestCases $documentationTestCases {
            ($help.Examples.Example.Remarks | Select-Object -First 1).Text | Should -Not -BeNullOrEmpty
        }
    }

    Context "Parameter Help" {
        # Should be a description for every parameter
        It "Should have help for parameter [<ParameterName>] for [<CommandName>]" -TestCases $commandParametersTestCases {
            $ParameterHelp.Description.Text | Should -Not -BeNullOrEmpty
        }

        # Required value in Help should match IsMandatory property of parameter
        It "Should have correct Mandatory value for parameter [<ParameterName>] for [<CommandName>]" -TestCases $commandParametersTestCases {
            $codeMandatory = $Parameter.IsMandatory.toString()
            $ParameterHelp.Required | Should -Be $codeMandatory
        }

        # Parameter type in Help should match code
        # It "help for $commandName has correct parameter type for $parameterName" {
        #     $codeType = $parameter.ParameterType.Name
        #     # To avoid calling Trim method on a null object.
        #     $helpType = if ($parameterHelp.parameterValue) { $parameterHelp.parameterValue.Trim() }
        #     $helpType | Should be $codeType
        # }

        # Shouldn't find extra parameters in help.
        It "Should have code parameter [<HelpParameterName>] for [<CommandName>]" -TestCases $helpParametersTestCases {
            $HelpParameterName -in $AllParameterNames | Should -Be $true
        }
    }

    Context "Help Links" {
        # Should have a valid uri if one is provided.
        it "Should be a valid link [<Link>] for [<CommandName>]" -TestCases $linksTestCases {
            $uri = $Link -as [System.URI]
            $uri.AbsoluteURI -ne $null -and $uri.Scheme -match '[http|https]'
        }
    }

}

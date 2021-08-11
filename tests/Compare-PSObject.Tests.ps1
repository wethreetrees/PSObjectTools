BeforeDiscovery {
    $baseDifferenceTestCases = @(
        @{
            ReferenceObject = [pscustomobject]@{
                Name = 'ObjectName'
            }
            DifferenceObject = [pscustomobject]@{
                Name = 'DifferentName'
            }
            ExpectedValue = [pscustomobject]@{
                Property        = '$_.Name'
                ReferenceValue  = 'ObjectName'
                DifferenceValue = 'DifferentName'
                Indicator      = 'NotEqual'
            }
        },
        @{
            ReferenceObject = [pscustomobject]@{
                Name = 'ObjectName'
                TestProperty = 'string', 'array', 'values'
            }
            DifferenceObject = [pscustomobject]@{
                Name = 'DifferentName'
                TestProperty = 'string', 'array', 'values', 'different'
            }
            ExpectedValue = @(
                [pscustomobject]@{
                    Property        = '$_.Name'
                    ReferenceValue  = 'ObjectName'
                    DifferenceValue = 'DifferentName'
                    Indicator      = 'NotEqual'
                },
                [pscustomobject]@{
                    Property        = '$_.TestProperty[3]'
                    ReferenceValue  = $null
                    DifferenceValue = 'different'
                    Indicator      = 'NotEqual'
                }
            )
        }
    )
}

Describe "Compare-PSObject Unit Tests" {

    BeforeAll {
        # if (Test-Path -Path $PSScriptRoot\..\dist) {
            Import-Module $PSScriptRoot\..\dist\PSObjectTools -Force
            Import-Module $PSScriptRoot\..\build_tools\tests\TestHelpers -DisableNameChecking -Force
        # } else {
        #     Write-Warning "Testing locally, importing function directly..."
        #     . $PSScriptRoot\..\src\Public\Format-PSObject.ps1
        #     . $PSScriptRoot\..\src\Public\Compare-PSObject.ps1
        # }
    }

    Context "Parameter Tests" {

        BeforeAll {
            $command = Get-Command -Name Compare-PSObject
        }

        It "Should have Mandatory ReferenceObject parameter" {
            $command | Should -HaveParameter ReferenceObject -Type [object] -Mandatory
        }

        It "Should have Mandatory DifferenceObject parameter" {
            $command | Should -HaveParameter DifferenceObject -Type [object] -Mandatory
        }

        It "Should have Depth parameter" {
            $command | Should -HaveParameter Depth -Type [int]
            $command | Should -HaveParameter Depth -Not -Mandatory
        }

        It "Should have IgnoreProperty parameter" {
            $command | Should -HaveParameter IgnoreProperty -Type [string[]]
            $command | Should -HaveParameter IgnoreProperty -Not -Mandatory
        }

        It "Should have IncludeEqual parameter" {
            $command | Should -HaveParameter IncludeEqual -Type [switch]
            $command | Should -HaveParameter IncludeEqual -Not -Mandatory
        }

        It "Should have ExcludeDifferent parameter" {
            $command | Should -HaveParameter ExcludeDifferent -Type [switch]
            $command | Should -HaveParameter ExcludeDifferent -Not -Mandatory
        }

    }

    Context "Identical Objects" {



    }

    Context "Base Property Differences" {

        It "Should return differences" -TestCases $baseDifferenceTestCases {
            $result = Compare-PSObject -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject
            $result | Should -BeObject $ExpectedValue
        }

    }

    Context "Nested Property Differences" {



    }

    Context "Differences Beyond Depth Limit" {



    }

}

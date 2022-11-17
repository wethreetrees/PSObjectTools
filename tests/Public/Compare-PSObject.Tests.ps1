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

    $noDifferenceTestCases = @(
        @{
            ReferenceObject = [pscustomobject]@{
                Name = 'ObjectName'
            }
            DifferenceObject = [pscustomobject]@{
                Name = 'ObjectName'
            }
        },
        @{
            ReferenceObject = [pscustomobject]@{
                Name = 'ObjectName'
                TestProperty = 'string', 'array', 'values'
            }
            DifferenceObject = [pscustomobject]@{
                Name = 'ObjectName'
                TestProperty = 'string', 'array', 'values'
            }
        }
    )
}

Describe "Compare-PSObject Unit Tests" {

    BeforeAll {
        $ModuleRoot = "$PSScriptRoot/../.."
        if (Test-Path -Path $ModuleRoot/dist) {
            Import-Module $ModuleRoot/dist/PSObjectTools -Force
            Import-Module $ModuleRoot/build_tools/tests/TestHelpers -DisableNameChecking -Force
        } else {
            Write-Warning "Testing locally, importing function directly..."
            . $ModuleRoot\src\Public\Format-PSObject.ps1
            . $ModuleRoot\src\Public\Compare-PSObject.ps1
        }
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

        It "Should not return any differences" -TestCases $noDifferenceTestCases {
            $result = Compare-PSObject -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject
            $result | Should -BeNullOrEmpty
        }

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

    Context "Array Differences" {

        It "Should return diffs when out of order" {
            $ReferenceObject = [pscustomobject]@{
                List = @(1, 2, 3, 4, 5)
            }
            $DifferenceObject = [pscustomobject]@{
                List = @(5, 1, 2, 3, 4)
            }
            $ExpectedValue = @(
                [pscustomobject]@{
                    Property        = '$_.List[0]'
                    ReferenceValue  = 1
                    DifferenceValue = 5
                    Indicator      = 'NotEqual'
                },
                [pscustomobject]@{
                    Property        = '$_.List[1]'
                    ReferenceValue  = 2
                    DifferenceValue = 1
                    Indicator      = 'NotEqual'
                },
                [pscustomobject]@{
                    Property        = '$_.List[2]'
                    ReferenceValue  = 3
                    DifferenceValue = 2
                    Indicator      = 'NotEqual'
                },
                [pscustomobject]@{
                    Property        = '$_.List[3]'
                    ReferenceValue  = 4
                    DifferenceValue = 3
                    Indicator      = 'NotEqual'
                },
                [pscustomobject]@{
                    Property        = '$_.List[4]'
                    ReferenceValue  = 5
                    DifferenceValue = 4
                    Indicator      = 'NotEqual'
                }
            )

            $result = Compare-PSObject -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject
            $result | Should -BeObject $ExpectedValue
        }

        It "Should return diffs when missing array item" {
            $ReferenceObject = [pscustomobject]@{
                List = @(1, 2, 3, 4, 5)
            }
            $DifferenceObject = [pscustomobject]@{
                List = @(1, 2, 3, 4)
            }
            $ExpectedValue = @(
                [pscustomobject]@{
                    Property        = '$_.List[4]'
                    ReferenceValue  = 5
                    DifferenceValue = $null
                    Indicator      = 'NotEqual'
                }
            )

            $result = Compare-PSObject -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject
            $result | Should -BeObject $ExpectedValue
        }

        It "Should not return diff when out of order, with '-MergeArrays'" {
            $ReferenceObject = [pscustomobject]@{
                List = @(1, 2, 3, 4, 5)
            }
            $DifferenceObject = [pscustomobject]@{
                List = @(5, 1, 2, 3, 4)
            }

            $result = Compare-PSObject -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -MergeArrays
            $result | Should -BeNullOrEmpty
        }

        It "Should return diff when missing array item, with '-MergeArrays'" {
            $ReferenceObject = [pscustomobject]@{
                List = @(1, 2, 3, 4, 5)
            }
            $DifferenceObject = [pscustomobject]@{
                List = @(1, 2, 3, 4)
            }
            $ExpectedValue = [pscustomobject]@{
                Property        = '$_.List'
                ReferenceValue  = @(1, 2, 3, 4, 5)
                DifferenceValue = @(1, 2, 3, 4)
                Indicator      = 'NotEqual'
            }

            $result = Compare-PSObject -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -MergeArrays
            $result | Should -BeObject $ExpectedValue
        }

    }

}

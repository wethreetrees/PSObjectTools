Describe "Format-PSObject Unit Tests" {

    BeforeAll {
        $ModuleRoot = "$PSScriptRoot\..\.."
        if (Test-Path -Path $ModuleRoot\dist) {
            Import-Module $ModuleRoot\dist\PSObjectTools -Force
        } else {
            Write-Warning "Testing locally, importing function directly..."
            . $ModuleRoot\src\Public\Format-PSObject.ps1
        }
    }

    Context "Parameter Tests" {

        BeforeAll {
            $command = Get-Command -Name Format-PSObject
        }

        It "Should have Mandatory InputObject parameter" {
            $command | Should -HaveParameter InputObject -Type [object] -Mandatory
        }

        It "Should have Depth parameter" {
            $command | Should -HaveParameter Depth -Type [int]
            $command | Should -HaveParameter Depth -Not -Mandatory
        }

        It "Should have IgnoreProperty parameter" {
            $command | Should -HaveParameter IgnoreProperty -Type [string[]]
            $command | Should -HaveParameter IgnoreProperty -Not -Mandatory
        }

        It "Should have Parent parameter" {
            $command | Should -HaveParameter Parent -Type [string]
            $command | Should -HaveParameter Parent -Not -Mandatory
        }

        It "Should have CurrentDepth parameter" {
            $command | Should -HaveParameter CurrentDepth -Type [int]
            $command | Should -HaveParameter CurrentDepth -Not -Mandatory
        }

    }

    Context "Functionality Tests" {
        
    }
}

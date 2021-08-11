Describe "Format-PSObject Unit Tests" {

    BeforeAll {
        if (Test-Path -Path $PSScriptRoot\..\dist) {
            Import-Module $PSScriptRoot\..\dist\PSObjectTools -Force
        } else {
            Write-Warning "Testing locally, importing function directly..."
            . $PSScriptRoot\..\src\Public\Format-PSObject.ps1
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

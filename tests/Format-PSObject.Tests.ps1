Describe "Format-PSObject Unit Tests" {

    BeforeAll {
        if (Test-Path -Path $PSScriptRoot\..\dist) {
            Import-Module $PSScriptRoot\..\dist\PSObjectTools -Force
        } else {
            Write-Warning "Testing locally, importing function directly..."
            . $PSScriptRoot\..\src\Public\Format-PSObject.ps1
        }
    }

    Context "Functionality Tests" {
        It 'should return zero for a zero length input array' {
            Format-PSObject | Should -Be 0
        }

        It 'should return the member value for a one member array' {
            Format-PSObject -Number 1 | Should -Be 1
        }

        It 'should return the member value for a one member array when given as string' {
            Format-PSObject -Number '1' | Should -Be 1
        }

        It 'should add whole number arrays' {
            Format-PSObject -Number 1, 2, 3 | Should -Be 6
        }

        It 'should add whole number arrays including negative numbers' {
            Format-PSObject -Number -1, 2, 3 | Should -Be 4
        }

        It 'should add whole number arrays including strings' {
            Format-PSObject -Number -1, '2', 3 | Should -Be 4
        }

        It 'should add fractions' {
            Format-PSObject -Number 1.1, 2.2, 3 | Should -BeLike 6.3  # Using -BeLike because comparing floats is annoying...
        }

        It 'should not add arrays of invalid data' {
            { Format-PSObject -Number 'notanumber', 2, 'invalid' } | Should -Throw
        }
    }
}

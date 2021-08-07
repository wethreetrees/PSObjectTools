#Requires -Module @{ ModuleName = 'Pester'; ModuleVersion = '5.2.2'; MaximumVersion = '5.*' }

Import-Module Pester -MinimumVersion 5.2.2 -MaximumVersion 5.*

<#
    .SYNOPSIS
        Perform PowerShell object deep comparison

    .DESCRIPTION
        The built-in cmdlet 'Compare-Object' is challenging to work with when you need to
        compare complex PowerShell objects with nested properties. The goal of Compare-PSObject
        is to alleviate these concerns and to allow for simple and comprehensive PowerShell
        object comparison.

        Compare-PSObject compares all nested properties of any PowerShell object, leveraging
        the Format-PSObject function. By default, all differing properties will be returned
        with the ReferenceObject and DifferenceObject values.

        Optionally, the IncludeEqual and ExcludeDifferent parameter can be provided to alter
        output. See the parameter help for more details.

    .PARAMETER ReferenceObject
        The primary object for comparison

    .PARAMETER DifferenceObject
        The secondary object for comparison

    .PARAMETER Depth
        The recursive limit for nested object property values

    .PARAMETER IgnorePropery
        An array of property names to skip formatting

    .PARAMETER IncludeEqual
        Include matching properties in the returned dataset

    .PARAMETER ExcludeDifferent
        Exclude differing properties in the returned dataset
#>
function Compare-PSObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReferenceObject,

        [Parameter(Mandatory)]
        [object]$DifferenceObject,

        [Parameter()]
        [int]$Depth,

        [Parameter()]
        [string[]]$IgnoreProperty,

        [Parameter()]
        [switch]$IncludeEqual,

        [Parameter()]
        [switch]$ExcludeDifferent
    )

    process {
        $formatObjectParams = @{}
        if ($IgnoreProperty) { $formatObjectParams['IgnoreProperty'] = $IgnoreProperty }
        if ($Depth) { $formatObjectParams['Depth'] = $Depth }

        $ReferenceObjectFormatted = $ReferenceObject | Format-PSObject @formatObjectParams
        $DifferenceObjectFormatted = $DifferenceObject | Format-PSObject @formatObjectParams

        $CompareObjectParams = @{
            ReferenceObject  = $ReferenceObjectFormatted
            DifferenceObject = $DifferenceObjectFormatted
            Property         = 'Path', 'Value'
            PassThru         = $true
        }
        # if ($IncludeEqual) { $CompareObjectParams['IncludeEqual'] = $true }
        # if ($ExcludeDifferent) { $CompareObjectParams['ExcludeDifferent'] = $true }

        $result = Compare-Object @CompareObjectParams -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent

        $result | Group-Object -Property Path | ForEach-Object {
            $group = $_
            $property = $group.Name
            if ($group.group.SideIndicator -match '<=|=>') {
                $referenceValue = ($group.group | Where-Object { $_.SideIndicator -eq '<=' }).Value
                $differenceValue = ($group.group | Where-Object { $_.SideIndicator -eq '=>' }).Value
                $indicator = 'NotEqual'
            } else {
                $referenceValue = $differenceValue = $group.group.Value
                $indicator = 'Equal'
            }

            [pscustomobject]@{
                Property        = $property
                ReferenceValue  = $referenceValue
                DifferenceValue = $differenceValue
                Indicator       = $indicator
            }
        }
    }

}

<#
    .SYNOPSIS
        Displays an object's nested properties and their values

    .DESCRIPTION
        Expands any complex PowerShell object for analysis or comparison. Format-PSObject returns
        a list of dot walked paths for each of the object's properties, along with values, up to
        the depth limit.

    .PARAMETER InputObject
        The object to format

    .PARAMETER Depth
        The recursive limit for nested object property values

    .PARAMETER IgnoreProperty
        An array of property names to skip formatting

    .PARAMETER Parent
        For internal use, but you can specify the base name of the variable displayed in the path

    .PARAMETER CurrentDepth
        For internal use

    .NOTES
        Adapted from https://www.red-gate.com/simple-talk/blogs/display-object-a-powershell-utility-cmdlet/
#>
function Format-PSObject {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [Parameter()]
        [int]$Depth = 10,

        [Parameter()]
        [object[]]$IgnoreProperty = @('#comment'),

        [Parameter(DontShow)]
        [string]$Parent = '$_',

        [Parameter(DontShow)]
        [int]$CurrentDepth = 0
    )

    process {
        if ($CurrentDepth -ge $Depth) {
            # Prevent runaway recursion
            Write-Warning (
                "Format-PSObject reached the depth limit [$Depth]. " +
                'Use the -Depth parameter to increase the recursion limit.'
            )
        }

        if ($null -eq $InputObject) {
            return $null
        }

        $ObjectTypeName = $InputObject.GetType().Name

        Write-Verbose "[$Parent] ObjectType = $ObjectTypeName"

        if ($ObjectTypeName -in 'HashTable', 'OrderedDictionary') {
            # If you can, force it to be a PSCustomObject in order to enable iterating over the properties
            $InputObject = [pscustomObject]$InputObject
            $ObjectTypeName = 'PSCustomObject'
        }

        if (-not ($InputObject.Count -gt 1)) {
            if ($ObjectTypeName -in @('PSCustomObject')) {
                $MemberType = 'NoteProperty'
            } else {
                $MemberType = 'Property'
            }

            $InputObject |
                Get-Member -MemberType $MemberType -Force |
                Where-Object { $_.Name -notin $IgnoreProperty } |
                ForEach-Object {
                    $property = $_

                    try {
                        $child = $InputObject.($property.Name)
                    } catch {
                        # Prevent crashing on write-only objects
                        $child = $null
                    }

                    if (
                        $child -eq $null -or
                        $child.GetType().BaseType.Name -eq 'ValueType' -or
                        $child.GetType().Name -in @('String', 'String[]')
                    ) {
                        [pscustomobject]@{ 'Path' = "$Parent.$($property.Name)"; 'Value' = $Child }
                    } elseif (($CurrentDepth + 1) -eq $Depth) {
                        Write-Warning (
                            "Format-PSObject reached the depth limit [$Depth]. " +
                            'Use the -Depth parameter to increase the recursion limit.'
                        )
                        [pscustomobject]@{ 'Path' = "$Parent.$($property.Name)"; 'Value' = $Child }
                    } else {
                        $FormatPSObjectParams = @{
                            InputObject    = $child
                            depth          = $Depth
                            IgnoreProperty = $IgnoreProperty
                            Parent         = "$Parent.$($property.Name)"
                            CurrentDepth   = $currentDepth + 1
                        }
                        Format-PSObject @FormatPSObjectParams
                    }
                }
        } else {
            0..($InputObject.Count - 1) | ForEach-Object {
                $iterator = $_
                $child = $InputObject[$iterator]

                if (
                    ($child -eq $null) -or #is the current child a value or a null?
                    ($child.GetType().BaseType.Name -eq 'ValueType') -or
                    ($child.GetType().Name -in @('String', 'String[]'))
                ) {
                    [pscustomobject]@{ 'Path' = "$Parent[$iterator]"; 'Value' = "$($child)" }
                } elseif (($CurrentDepth + 1) -eq $Depth) {
                    Write-Warning (
                        "Format-PSObject reached the depth limit [$Depth]. " +
                        'Use the -Depth parameter to increase the recursion limit.'
                    )
                    [pscustomobject]@{ 'Path' = "$Parent[$iterator]"; 'Value' = "$($child)" }
                } else {
                    $FormatPSObjectParams = @{
                        InputObject    = $child
                        depth          = $Depth
                        IgnoreProperty = $IgnoreProperty
                        Parent         = "$Parent[$iterator]"
                        CurrentDepth   = $currentDepth + 1
                    }
                    Format-PSObject @FormatPSObjectParams
                }
            }
        }
    }
}

function Should-BeObject($ActualValue, $ExpectedValue, [switch] $Negate, [string] $Because) {
    <#
    .SYNOPSIS
        Asserts that each property value of the provided object
        matches the expected object exactly.
    .EXAMPLE
        @{name = 'test'; value = @{num = 12345}} | Should -BeObject @{name = 'test'; value = @{num = 12345}}

        Checks if all object properties are the same. This should pass.
    .EXAMPLE
        @{name = 'test'; value = @{num = 54321}} | Should -BeObject @{name = 'test'; value = @{num = 12345}}

        Checks if all object properties are the same. This should not pass.
    #>

    $results = Compare-PSObject -ReferenceObject $ExpectedValue -DifferenceObject $ActualValue -IncludeEqual:$Negate
    [bool] $succeeded = -not ('NotEqual' -in $results.Indicator)
    if ($Negate) { $succeeded = -not $succeeded }

    if (-not $succeeded) {
        if ($Negate) {
            $failureMessage = (
                "Objects should be the different, but they were the same: `n`n" +
                "$($results | Out-String)"
            )
        } else {
            $failureMessage = (
                "Objects should be the same, but differences were found: `n`n" +
                "$($results | Out-String)"
            )
        }
    }

    return New-Object psobject -Property @{
        Succeeded      = $succeeded
        FailureMessage = $failureMessage
    }
}

Add-ShouldOperator -Name BeObject -Test ${function:Should-BeObject} -InternalName 'Should-BeObject'
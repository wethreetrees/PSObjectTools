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

    .PARAMETER IgnoreProperty
        An array of property names to skip during comparison

    .PARAMETER IncludeEqual
        Include matching properties in the returned dataset

    .PARAMETER ExcludeDifferent
        Exclude differing properties in the returned dataset

    .EXAMPLE
        Compare-PSObject -ReferenceObject @{value1 = 'testvalue'} -DifferenceObject @{value1 = 'testvalue'}

        Perform a simple object comparison between two matching objects.
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
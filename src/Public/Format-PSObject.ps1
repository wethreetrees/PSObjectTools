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

    .EXAMPLE
        Format-PSObject -InputObject @{value1 = 'testvalue'; value2 = @{nestedValue = 'nested'}}

        Create a property mapping of the 'InputObject' properties and their respective values

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
        [int]$Depth = 5,

        [Parameter()]
        [string[]]$IgnoreProperty,

        [Parameter(DontShow)]
        [string]$Parent = '$_',

        [Parameter(DontShow)]
        [int]$CurrentDepth = 0
    )

    begin {
        if ($CurrentDepth -eq 0) { $reachedDepthLimit = $false }
    }

    process {
        if ($CurrentDepth -ge $Depth) {
            # Prevent runaway recursion
            $Script:reachedDepthLimit = $true
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

        if (-not ($InputObject.Count -gt 1) -and -not ($InputObject -is [System.Collections.IEnumerable])) {
            if ($ObjectTypeName -in @('PSCustomObject')) {
                $MemberType = 'NoteProperty'
            } else {
                $MemberType = 'Property'
            }

            if ($InputObject) {
                Get-Member -InputObject $InputObject -MemberType $MemberType -Force |
                Where-Object { $_.Name -notin $IgnoreProperty } |
                ForEach-Object {
                    $property = $_

                    try {
                        $child = $InputObject.($property.Name)
                        $psTypeName = try { $Child.GetType() } catch { $null }
                    } catch {
                        # Prevent crashing on write-only objects
                        $child = $null
                    }

                    if (
                        $child -eq $null -or
                        $child.GetType().BaseType.Name -eq 'ValueType' -or
                        $child.GetType().Name -in @('String', 'String[]')
                    ) {
                        [pscustomobject]@{
                            'Path'       = "$Parent.$($property.Name)"
                            'Value'      = $Child
                            'PSTypeName' = $psTypeName
                            'Depth'      = $CurrentDepth
                        }
                    } elseif (($CurrentDepth + 1) -eq $Depth) {
                        $Script:reachedDepthLimit = $true
                        [pscustomobject]@{
                            'Path'       = "$Parent.$($property.Name)"
                            'Value'      = $Child
                            'PSTypeName' = $psTypeName
                            'Depth'      = $CurrentDepth
                        }
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
            }
        } else {
            0..($InputObject.Count - 1) | ForEach-Object {
                $iterator = $_
                $child = $InputObject[$iterator]
                $psTypeName = try { $Child.GetType() } catch { $null }

                if (
                    ($null -eq $child) -or #is the current child a value or a null?
                    ($child.GetType().BaseType.Name -eq 'ValueType') -or
                    ($child.GetType().Name -in @('String', 'String[]'))
                ) {
                    [pscustomobject]@{
                        'Path'       = "$Parent[$iterator]"
                        'Value'      = "$child"
                        'PSTypeName' = $psTypeName
                        'Depth'      = $CurrentDepth
                    }
                } elseif (($CurrentDepth + 1) -eq $Depth) {
                    $Script:reachedDepthLimit = $true
                    [pscustomobject]@{
                        'Path'       = "$Parent[$iterator]"
                        'Value'      = "$child"
                        'PSTypeName' = $psTypeName
                        'Depth'      = $CurrentDepth
                    }
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

    end {
        if ($CurrentDepth -eq 0 -and $reachedDepthLimit) {
            Write-Warning (
                "Format-PSObject reached the depth limit [$Depth]. " +
                'Use the -Depth parameter to increase the recursion limit.'
            )
        }
    }
}
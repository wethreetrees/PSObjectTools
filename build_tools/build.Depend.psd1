# DO NOT MODIFY!!
@{
    PSDependOptions       = @{
        Target    = '$DependencyFolder\_build_dependencies_\'
        AddToPath = $true
        Tags      = 'Build'
    }
    PSDepend              = '0.3.8'
    PSDeploy              = '1.0.5'
    BuildHelpers          = '2.0.15'
    Configuration         = '1.3.1'
    Plaster               = '1.1.3'
    InvokeBuild           = @{
        Version = '5.6.3'
        Tags    = 'Build', 'CodeHealth'
    }
    Pester         = @{
        Name    = 'Pester'
        Version = '5.3.1'
        Tags    = 'Test'
        Target  = '$DependencyFolder\_build_dependencies_\Test\'
    }
    # Pester_4_10_1         = @{
    #     Name    = 'Pester'
    #     Version = '4.10.1'
    #     Tags    = 'CodeHealth'
    #     Target  = '$DependencyFolder\_build_dependencies_\CodeHealth\'
    # }
    PSScriptAnalyzer      = @{
        Version = '1.19.1'
        Tags    = 'CodeHealth'
        Target  = '$DependencyFolder\_build_dependencies_\CodeHealth\'
    }
    # PSCodeHealth          = @{
    #     Version        = '0.2.26'
    #     Tags           = 'CodeHealth'
    #     Target         = '$DependencyFolder\_build_dependencies_\CodeHealth\'
    #     DependsOn      = 'Pester_4_10_1'
    # }
}

# DO NOT MODIFY!!
@{
    PSDependOptions = @{
        Target    = '$DependencyFolder/_build_dependencies_/'
        AddToPath = $true
        Tags      = 'Build'
    }
    InvokeBuild            = '5.6.3'
    PSDeploy               = '1.0.5'
    BuildHelpers           = '2.0.15'
    Configuration          = '1.3.1'
    PSScriptAnalyzer       = '1.19.1'
    NameIT                 = ''
    Pester_5_0_4           = @{
        Name    = 'Pester'
        Version = '5.0.4'
        Tags    = 'Test'
        Target  = '$DependencyFolder/_build_dependencies_/Test/'
    }
    Pester_4_10_1          = @{
        Name    = 'Pester'
        Version = '4.10.1'
        Tags    = 'CodeHealth'
        Target  = '$DependencyFolder/_build_dependencies_/CodeHealth/'
    }
    PSCodeHealth           = @{
        Version = '0.2.26'
        DependencyType = 'PSGalleryNuget'
        Tags    = 'CodeHealth'
        Target  = '$DependencyFolder/_build_dependencies_/CodeHealth/'
        DependsOn = 'Pester_4_10_1'
    }
}

Describe 'Module manifest' {

    BeforeAll {
        $moduleName         = $env:BHProjectName
        $outputDir          = Join-Path -Path $ENV:BHProjectPath -ChildPath 'Output'
        $outputModDir       = Join-Path -Path $outputDir -ChildPath $env:BHProjectName
        $outputManifestPath = Join-Path -Path $outputModDir -Child "$($moduleName).psd1"
        $changelogPath      = Join-Path -Path $env:BHProjectPath -Child 'CHANGELOG.md'
    }
    Context 'Validation' {
        BeforeAll {
            foreach ($line in (Get-Content $changelogPath)) {
                if ($line -match "^##\s\[(?<Version>(\d+\.){1,3}\d+)\]") {
                    $changelogVersion = $matches.Version
                    break
                }
            }
            $manifest = Test-ModuleManifest -Path $outputManifestPath -ErrorAction Ignore -WarningAction Ignore
        }

        It 'has a valid manifest' {
            $manifest | Should -Not -BeNullOrEmpty
        }

        It 'has a valid name in the manifest' {
            $manifest.Name | Should -Be $env:BHProjectName
        }

        It 'has a valid root module' {
            $manifest.RootModule | Should -Be "$($moduleName).psm1"
        }

        It 'has a valid version in the manifest' {
            $manifest.Version -as [Version] | Should -Not -BeNullOrEmpty
        }

        It 'has a valid description' {
            $manifest.Description | Should -Not -BeNullOrEmpty
        }

        It 'has a valid author' {
            $manifest.Author | Should -Not -BeNullOrEmpty
        }

        It 'has a valid guid' {
            { [guid]::Parse($manifest.Guid) } | Should -Not -Throw
        }

        It 'has a valid copyright' {
            $manifest.CopyRight | Should -Not -BeNullOrEmpty
        }

        It 'has a valid version in the changelog' {
            $changelogVersion | Should -Not -BeNullOrEmpty
            $changelogVersion -as [Version] | Should -Not -BeNullOrEmpty
        }

        It 'changelog and manifest versions are the same' {
            $changelogVersion -as [Version] | Should -Be ( $manifest.Version -as [Version] )
        }
    }

}

# PSObjectTools

## Description

Functions to enable advanced PSObject analysis and comparison.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Installing

This module can be installed from the (nuget.deloitteresources.com) repository. Repository setup instructions can be found on that site.

Install the latest stable release

```ps
Install-Module -Name PSObjectTools -Repository PSGallery
```

### Basic Usage

Import the installed module

```ps
Import-Module PSObjectTools
```

Import the module during local development. This will build and import the latest local changes.

```ps
.\build.ps1 -Task Import
```

*There are some issues that arise during development due any required assemblies. Assemblies are loaded into your PowerShell session and cannot be removed. If you experience any issues while making changes and re-importing the module, please close all of your active PowerShell sessions.*

## Running the tests

Tests are located in the `PSObjectTools\tests` directory.

The following command will build and test the module.

```ps
.\build.ps1
```

### And coding style tests

Static code analysis using PSCodeHealth for code quality and maintainability analysis. PSCodeHealth covers the following metrics:

- Code length
- Code complexity
- Code smells, styling issues and violations of best practices
- Comment-based help

```ps
.\build.ps1 -Task CodeHealth
```

## Advanced Usage



## Build

The module is built with [InvokeBuild](https://github.com/nightroman/Invoke-Build).

When making changes, the project should be built and tested on your machine prior to pushing any changes to your branch.

For development changes, build and import with the following command:

```ps
.\build -Task Import
```

Before committing code, build with the following command:

```ps
# This command will take a long time to run, it is not recommended until code is ready to be committed!
.\build.ps1
```

The build steps are documented in the following graph.

[Build Graph](./docs/BuildGraph.html)

## Release

All new development changes should be merged into the `develop` branch for release as a `-prerelease` version. For emergency patches, the code should be merged to both the `develop` and `release` branches.

Once a `-prerelease` version is determined to be stable and ready for production, the code should be merged from the `develop` branch into the `release` branch.

Alternatively, code can just be merged directly into the main branch, bypassing the `-prerelease` process.

## Versioning

This project uses [semantic versioning](https://semver.org/).

1. MAJOR version when you make incompatible API changes,
2. MINOR version when you add functionality in a backwards compatible manner, and
3. PATCH version when you make backwards compatible bug fixes.

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

All versioning is handled in the [build script](module.build.ps1).

## Authors

- **Richardson, Tyler**

## Acknowledgments

Inspired by Phil Factor's work, as seen here: https://www.red-gate.com/simple-talk/blogs/display-object-a-powershell-utility-cmdlet/

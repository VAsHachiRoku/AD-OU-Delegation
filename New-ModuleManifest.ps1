New-ModuleManifest `
    -Path .\AdSchemaMap\AdGuidMap.psd1 `
    -NestedModules @('.\AdSchemaFunctions\New-ADDExtendedRightMap.psm1', '.\AdSchemaFunctions\New-ADDGuidMap.psm1') `
    -Guid (New-Guid) `
    -ModuleVersion '1.0.0.0' `
    -Description 'Functions used to get the AD Schema GUID of objects and extended MAPs' `
    -PowerShellVersion $PSVersionTable.PSVersion.ToString() `
    -FunctionsToExport @('New-ADDExtendedRightMap', 'New-ADDGuidMap')

Import-Module .\AdSchemaMap\AdGuidMap.psd1
Get-Command -Module AdGuidMap
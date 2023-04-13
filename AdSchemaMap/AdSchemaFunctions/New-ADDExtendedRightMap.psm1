function New-ADDExtendedRightMap {
    <#
    .SYNOPSIS
        Creates a extended rights map for the delegation part
    .DESCRIPTION
        Creates a extended rights map for the delegation part
    .EXAMPLE
        PS C:\> New-ADDExtendedRightsMap
    .NOTES
        Author: Constantin Hager https://github.com/constantinhager
        Date: 06.08.2019
    #>
    $rootdse = Get-ADRootDSE
    $ExtendedMapParams = @{
        SearchBase = ($rootdse.ConfigurationNamingContext)
        LDAPFilter = "(&(objectclass=controlAccessRight)(rightsguid=*))"
        Properties = ("displayName", "rightsGuid")
    }
    $extendedrightsmap = @{ }
    Get-ADObject @ExtendedMapParams | ForEach-Object { $extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid }
    return $extendedrightsmap
}
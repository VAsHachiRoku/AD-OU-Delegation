#Requires -Version 7.0

<#
.Synopsis
Script requires a JSON source file for custom RBAC Active Directory OU delegation of Allow attribute changes
.Description
A JSON file is used as a golden source to delegation permissions on the region OUs for Users, Groups, and Computer objects
.Parameter JsonPath
This is a Mandatory parameter to the full path of the JSON delegation input file.
.Parameter SkipRemoval
This is an optional parameter that should only be used when delegatin permissions for the first time as there have been no group delegations to remove.
.Example
Set-RbacDelegation -JsonFile C:\Files\Delegation.json
Delegation of ACLs to the Regional OUs based on the JSON file as input
.Example
Set-RbacDelegation -JsonFile C:\Files\Delegation.json -SkipRemoval
Used only during the first delegation execution to skip the removal of groups that have not been delegated on the regional OUs
.Inputs
Requires a JSON file with specific objects for the script to execute properly
.Outputs
Regional Organizational Units will have the correct ACL's applied to manage Users, Groups, and Computer objects
#>
Param(

    [Parameter(Mandatory = $true)]
    [string]$JsonPath,
    [Parameter(Mandatory = $false)]
    [Switch]$SkipRemoval

) #end param


#Import Models
Import-Module AdmPwd.PS -SkipEditionCheck -ErrorAction Stop
Import-Module ActiveDirectory -SkipEditionCheck -ErrorAction Stop
Import-Module "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdSchemaMap\AdGuidMap.psd1" -SkipEditionCheck -ErrorAction Stop

#Create Map Object GUID from the Schema for AD Delegation of objects scripts are not on GitHub but author can be fround at https://github.com/constantinhager
$GuidMap = New-ADDGuidMap
$ExtendedRight = New-ADDExtendedRightMap

#Get the Content of the delegation JSON source file from the required parameter
$Json = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json

#Loop through each Regional OU within the JSON file
foreach ($OU in $Json.OrganizationUnits) {
    #Set the OU DN to a variable
    $RegionAdOuDn = $OU.DN
    #Combine for full AD Provide Drive path from JSON file DN:
    $RegionAdDriveOU = "AD:\" + $RegionAdOuDn
    #Variable containing the 4 character Region code from the JSON file Code:
    $RegionCode = $OU.Code

    #Loop through each User Permission Group within the JSON file
    foreach ($UserSAM in $Json.Groups.UsersSAM) {
        #Combine the Region Code and the UserSAM group example APAC and -A-User is APAC-A-User
        $RegionUserSAM = $RegionCode + $UserSAM
        #Get the SID of the User Group object and create a new PS Object
        $RegionUserSAMSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $RegionUserSAM).SID
    
        #If Group name contains the -A-Users, then get the specific allowed properties from the Json file Delegations: then UserAllow:
        If ($UserSAM -match "-A-Users") {               
            #If statement for the -SkipRemoval parameter to assist with first run delegation scenarios where there is no existing group to remove
            if ($SkipRemoval){
                #Get the all current ACLs on the Regional OU
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
            } else {
                #If -SkipRemoval is not present which should be the default for each additional execution of the script post the first run delegation.
                #Get the all current ACLs on the Regional OU
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
                #Get the Regional OU
                $RemoveAcl = Get-Acl $RegionAdDriveOU
                #Create an ACL removal object
                $RemoveAcl.PurgeAccessRules($RegionUserSAMSID)
                #Remove the REGION-A-User group from the Region OU
                Set-ACL -Path $RegionAdDriveOU -AclObject $RemoveAcl
                #Get the all current ACLs on the Regional OU after the group has been removed
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
            }

            #Loop through allowed properties from the JSON file for the specific group Delegations: then UserAllow:
            foreach ($AuthRule in $Json.Delegations.UserAllow) {
                    #The SID of the REGION-A-Users, Property from the JSON such as Displayname, Allow Permission, inherited to child OUs, Object type delegated to User                    
                    #SID of the REGION-A-User Group
                    #Access Rights property https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-8.0
                    #Allow to a specific property such as givenName based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-7.0
                    #Delegated to User Objects based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-8.0
                    $UserAAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $RegionUserSAMSID,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$AuthRule],
                                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
                )
                
                #Combine each delegated into a single ACL
                $UserAAcl.AddAccessRule($UserAAce)
            }
            
            #Add all the Allows ACLs to the specific Region OU
            Set-ACL -Path $RegionAdDriveOU -AclObject $UserAAcl

        } elseif ($UserSAM -match "-S-Users") {               
            #If statement for the -SkipRemoval parameter to assist with first run delegation scenarios where there is no existing group to remove
            if ($SkipRemoval){
                #Get the all current ACLs on the Regional OU
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
            } else {
                #If -SkipRemoval is not present which should be the default for each additional execution of the script post the first run delegation.
                #Get the all current ACLs on the Regional OU
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
                #Get the Regional OU
                $RemoveAcl = Get-Acl $RegionAdDriveOU
                #Create an ACL removal object
                $RemoveAcl.PurgeAccessRules($RegionUserSAMSID)
                #Remove the REGION-S-User group from the Region OU
                Set-ACL -Path $RegionAdDriveOU -AclObject $RemoveAcl
                #Get the all current ACLs on the Regional OU after the group has been removed
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
            }

            #Loop through allowed properties from the JSON file for the specific group Delegations: then UserSecurity:
            foreach ($AuthRule in $Json.Delegations.UserSecurity) {
                    #The SID of the REGION-S-Users, Property from the JSON such as Displayname, Allow Permission, inherited to child OUs, Object type delegated to User                    
                    #SID of the REGION-S-User Group
                    #Access Rights property https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-8.0
                    #Allow to a specific property such as givenName based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-7.0
                    #Delegated to User Objects based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-8.0
                    $UserAAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $RegionUserSAMSID,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$AuthRule],
                                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
                )
                
                #Combine each delegated into a single ACL
                $UserAAcl.AddAccessRule($UserAAce)
            }
            
            #Add all the Allows ACLs to the specific Region OU
            Set-ACL -Path $RegionAdDriveOU -AclObject $UserAAcl

        } elseif ($UserSAM -match "-P-Users") {               
            #If statement for the -SkipRemoval parameter to assist with first run delegation scenarios where there is no existing group to remove
            if ($SkipRemoval){
                #Get the all current ACLs on the Regional OU
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
            } else {
                #If -SkipRemoval is not present which should be the default for each additional execution of the script post the first run delegation.
                #Get the all current ACLs on the Regional OU
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
                #Get the Regional OU
                $RemoveAcl = Get-Acl $RegionAdDriveOU
                #Create an ACL removal object
                $RemoveAcl.PurgeAccessRules($RegionUserSAMSID)
                #Remove the REGION-P-User group from the Region OU
                Set-ACL -Path $RegionAdDriveOU -AclObject $RemoveAcl
                #Get the all current ACLs on the Regional OU after the group has been removed
                $UserAAcl = Get-Acl -Path $RegionAdDriveOU
            }
            
            #Loop through allowed properties from the JSON file for the specific group Delegations: then UserSecurity:
            foreach ($AuthRule in $Json.Delegations.UserPassword) {
                #The SID of the REGION-P-Users, Property from the JSON which is password reset Object type delegated to User                    
                #SID of the REGION-P-User Group
                #Access Rights property https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-8.0
                #Allow to a specific property such as givenName based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-7.0
                #Delegated to User Objects based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-8.0
                $UserAAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $RegionUserSAMSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$AuthRule],
                            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
                )
            
                #Combine each delegated into a single ACL
                $UserAAcl.AddAccessRule($UserAAce)
            }

            #Add all the Allows ACLs to the specific Region OU
            Set-ACL -Path $RegionAdDriveOU -AclObject $UserAAcl

        } else {
            #A User group has not been defined in the JSON and a matching elseif statement
            stop
        }

    } #End of User Groups Loops

    #Loop through each Group Permission Group within the JSON file
    foreach ($GroupSAM in $Json.Groups.GroupsSAM) {
        #Combine the Region Code and the GroupSAM group example APAC and -A-Groups is APAC-A-Groups
        $RegionGroupSAM = $RegionCode + $GroupSAM
        #Get the SID of the Group Group object and create a new PS Object
        $RegionGroupSAMSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $RegionGroupSAM).SID

        #If Group name contains the -A-Groups, then get the specific allowed properties from the Json file Delegations: then GroupAllow:
        If ($GroupSAM -match "-A-Groups") {               
            #If statement for the -SkipRemoval parameter to assist with first run delegation scenarios where there is no existing group to remove
            if ($SkipRemoval){
                #Get the all current ACLs on the Regional OU
                $GroupAAcl = Get-Acl -Path $RegionAdDriveOU
            } else {
                #If -SkipRemoval is not present which should be the default for each additional execution of the script post the first run delegation.
                #Get the all current ACLs on the Regional OU
                $GroupAAcl = Get-Acl -Path $RegionAdDriveOU
                #Get the Regional OU
                $RemoveAcl = Get-Acl $RegionAdDriveOU
                #Create an ACL removal object
                $RemoveAcl.PurgeAccessRules($RegionGroupSAMSID)
                #Remove the REGION-A-Groups group from the Region OU
                Set-ACL -Path $RegionAdDriveOU -AclObject $RemoveAcl
                #Get the all current ACLs on the Regional OU after the group has been removed
                $GroupAAcl = Get-Acl -Path $RegionAdDriveOU
            }

            #Loop through allowed properties from the JSON file for the specific group Delegations: then GroupAllow:
            foreach ($AuthRule in $Json.Delegations.GroupAllow) {
                    #The SID of the REGION-A-Groups, Property from the JSON such as Displayname, Allow Permission, inherited to child OUs, Object type delegated to Groups                    
                    #SID of the REGION-A-Groups Group
                    #Access Rights property https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-8.0
                    #Allow to a specific property such as givenName based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-7.0
                    #Delegated to Group Objects based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-8.0
                    $GroupAAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $RegionGroupSAMSID,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$AuthRule],
                                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
                )
                
                #Combine each delegated into a single ACL
                $GroupAAcl.AddAccessRule($GroupAAce)
            }
            
            #Add all the Allows ACLs to the specific Region OU
            Set-ACL -Path $RegionAdDriveOU -AclObject $GroupAAcl

        } elseif ($GroupSAM -match "-S-Groups") {               
            #If statement for the -SkipRemoval parameter to assist with first run delegation scenarios where there is no existing group to remove
            if ($SkipRemoval){
                #Get the all current ACLs on the Regional OU
                $GroupAAcl = Get-Acl -Path $RegionAdDriveOU
            } else {
                #If -SkipRemoval is not present which should be the default for each additional execution of the script post the first run delegation.
                #Get the all current ACLs on the Regional OU
                $GroupAAcl = Get-Acl -Path $RegionAdDriveOU
                #Get the Regional OU
                $RemoveAcl = Get-Acl $RegionAdDriveOU
                #Create an ACL removal object
                $RemoveAcl.PurgeAccessRules($RegionGroupSAMSID)
                #Remove the REGION-S-Groups group from the Region OU
                Set-ACL -Path $RegionAdDriveOU -AclObject $RemoveAcl
                #Get the all current ACLs on the Regional OU after the group has been removed
                $GroupAAcl = Get-Acl -Path $RegionAdDriveOU
            }

            #Loop through allowed properties from the JSON file for the specific group Delegations: then GroupSecurity:
            foreach ($AuthRule in $Json.Delegations.GroupSecurity) {
                    #The SID of the REGION-S-Groups, Property from the JSON such as Members and ManagedBy inherited to child OUs, Object type delegated to Groups                    
                    #SID of the REGION-S-Groups Group
                    #Access Rights property https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-8.0
                    #Allow to a specific property such as givenName based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-7.0
                    #Delegated to Group Objects based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-8.0
                    $GroupAAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $RegionGroupSAMSID,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$AuthRule],
                                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
                )
                
                #Combine each delegated into a single ACL
                $GroupAAcl.AddAccessRule($GroupAAce)
            }
            
            #Add all the Allows ACLs to the specific Region OU
            Set-ACL -Path $RegionAdDriveOU -AclObject $GroupAAcl

        } else {
            #A group has not been defined in the JSON and a matching elseif statement
            stop
        }

    } #End of Group Groups Loops

    #Loop through each Computer Permission Groups within the JSON file
    foreach ($ComputerSAM in $Json.Groups.ComputersSAM) {
        #Combine the Region Code and the ComputerSAM group example APAC and -A-Computers is APAC-A-Computers
        $RegionComputerSAM = $RegionCode + $ComputerSAM
        #Get the SID of the Computer Group object and create a new PS Object
        $RegionComputerSAMSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $RegionComputerSAM).SID

        #If Group name contains the -A-Computers, then get the specific allowed properties from the Json file Delegations: then ComputerAllow:
        If ($ComputerSAM -match "-A-Computers") {               
            #If statement for the -SkipRemoval parameter to assist with first run delegation scenarios where there is no existing group to remove
            if ($SkipRemoval){
                #Get the all current ACLs on the Regional OU
                $ComputerAAcl = Get-Acl -Path $RegionAdDriveOU
            } else {
                #If -SkipRemoval is not present which should be the default for each additional execution of the script post the first run delegation.
                #Get the all current ACLs on the Regional OU
                $ComputerAAcl = Get-Acl -Path $RegionAdDriveOU
                #Get the Regional OU
                $RemoveAcl = Get-Acl $RegionAdDriveOU
                #Create an ACL removal object
                $RemoveAcl.PurgeAccessRules($RegionComputerSAMSID)
                #Remove the REGION-A-Computers group from the Region OU
                Set-ACL -Path $RegionAdDriveOU -AclObject $RemoveAcl
                #Get the all current ACLs on the Regional OU after the group has been removed
                $ComputerAAcl = Get-Acl -Path $RegionAdDriveOU
            }

            #Loop through allowed properties from the JSON file for the specific group Delegations: then ComputerAllow:
            foreach ($AuthRule in $Json.Delegations.ComputerAllow) {
                    #The SID of the REGION-A-Computers, Property from the JSON such as Create and Delete permission inherited to child OUs, Object type delegated to Computers                    
                    #SID of the REGION-A-Computers Group
                    #Access Rights property https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=windowsdesktop-8.0
                    #Allow to a specific property such as givenName based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-7.0
                    #Delegated to Computer Objects based on GUID https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=windowsdesktop-8.0
                    $ComputerAAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $RegionComputerSAMSID,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$AuthRule],
                                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
                )
                
                #Combine each delegated into a single ACL
                $ComputerAAcl.AddAccessRule($ComputerAAce)
            }
            
            #Add all the Allows ACLs to the specific Region OU
            Set-ACL -Path $RegionAdDriveOU -AclObject $ComputerAAcl

        } elseif ($ComputerSAM -match "-L-Computers") {   

            #Sets the read LAPS permission on the Computer Objects
            Set-AdmPwdReadPasswordPermission -Identity $RegionAdOuDn -AllowedPrincipals $RegionComputerSAM | Out-Null
            #Sets the expire LAPS permission on the Computer Objects
            Set-AdmPwdResetPasswordPermission -Identity $RegionAdOuDn -AllowedPrincipals $RegionComputerSAM | Out-Null

          } else {
            #A Computer has not been defined in the JSON and a matching elseif statement
            stop
        }

    } #End of Computer Groups Loops

} #End of OU Loop
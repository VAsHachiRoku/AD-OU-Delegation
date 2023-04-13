#https://the-itguy.de/delegate-access-in-active-directory-with-powershell/
#https://learn.microsoft.com/en-us/answers/questions/948724/delegate-move-object-in-active-directory-using-pow
$group = "Domain\GroupName"
$acl = Get-Acl -Path "AD:\OU=APAC,OU=Prod,DC=lab,DC=com"
$acl.Access.Where({ $_.IdentityReference -eq $group})
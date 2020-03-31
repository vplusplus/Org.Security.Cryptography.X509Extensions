

# List and print
$certs = Get-ChildItem -Path cert:\CurrentUser\My
$certs

# Loop and print
Foreach ($c IN $certs) 
{
   Write-Host $c.SubjectName.Name
   Write-Host $c.Issuer
   Write-Host $c.Thumbprint
   Write-Host "HasPrivateKey?" $c.HasPrivateKey
   Write-Host "SignatureAlgorithm" $c.SignatureAlgorithm.FriendlyName
}

# Find and print
$t = "TheThumbprint"
$c = Get-ChildItem -Path cert:\CurrentUser\My\$t
Write-Host $c.ToString($true)



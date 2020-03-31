

# List of certs
$certs = Get-ChildItem -Path cert:\CurrentUser\My

# Print Thumbprint
$certs

# Loop and print specific property
Foreach ($c IN $certs) 
{
	Write-Host $c.SubjectName.Name
	Write-Host $c.Issuer
	Write-Host $c.Thumbprint
    Write-Host "HasPrivateKey?" $c.HasPrivateKey
    Write-Host "SignatureAlgorithm" $c.SignatureAlgorithm.FriendlyName
}

# Find cert by Thumbprint, print details
$thumb = "TheThumbprint"
$c = Get-ChildItem -Path cert:\CurrentUser\My\$$thumb
Write-Host $c.ToString($true)

 

# Use of self-signed=certs is NOT recommonded for real world application workloads.
# The helpers below can be used at best for 
# Local development and unit testing 
# Strictly server-to-server communication with no user-intervention with-in a controlled private network in NON production usecases.

$dnsName = "org.poc.myapplication"
$outputPath = "D:\Junk"

# Collect password for the PFX file. Username is ignored.
$pfxCredentials = Get-Credential -Message "Enter a password for the PFX" -UserName "$dnsName"

# Output file names.
$pfxFileName = "$outputPath\$dnsName.pfx"
$cerFileName = "$outputPath\$dnsName.cer"
$thumbprintFileName = "$outputPath\$dnsName.thumb.txt"

Write-Host "Creating (and registering) self-signed certificate. DNS Name: $dnsName"
$cert = New-SelfSignedCertificate `
	-DnsName $dnsName `
	-CertStoreLocation Cert:\CurrentUser\My `
	-KeyLength 1024 `
	-KeyAlgorithm RSA
	# -KeyExportPolicy Exportable
	# -KeySpec KeyExchange 

# Retrieve and show cert info
$thumbprint = $cert.Thumbprint
$c = Get-Item Cert:\CurrentUser\My\$thumbprint
Write-Host $c.ToString($true)

# Export the certificate to .PFX, .CER and the thumbprint
Write-Host "Exporting PFX, CER and thumbprint"
Export-PfxCertificate -Cert $cert -FilePath $pfxFileName -Password $pfxCredentials.Password | Out-Null
Export-Certificate -Cert $cert -FilePath $cerFileName | Out-Null
Set-Content -Path $thumbprintFileName -Value $cert.Thumbprint | Out-Null

# Print the file names and the thumbprint
Write-Host "--------------------------------------------------------------------"
Write-Host "Generated..."
Write-Host "--------------------------------------------------------------------"
$pfxFileName
$cerFileName
$thumbprintFileName

# Print the certificate Thumbprint
Write-Host "Thumbprint:"
$cert.Thumbprint

# REMOVE CERT from local store.
Write-Host "--------------------------------------------------------------------"
Write-Host "IMP: Removing the self-signed-certificate from Cert:\CurrentUser\My"
Write-Host "IMP: Import the .pfx again in the target machine"
Write-Host "--------------------------------------------------------------------"
Get-ChildItem -Path cert:\CurrentUser\My\$thumbprint | Remove-Item
Write-Host "Removed the certificate."

# Use following command to import the PFX using powershell.
# Import-PfxCertificate -Exportable -CertStoreLocation Cert:\LocalMachine\My -FilePath $pfxFileName -Password $securePassword


# Create Self-Signed Code Signing Certificate for Luckyverse Security
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Luckyverse Security" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)

# Copy certificate to Trusted Root Certification Authorities
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()

# Sign NetPhantom binaries
$exe1 = "c:\Users\Lucky\Downloads\NetPhantom-main\NetPhantom-main\installers\windows\dist\NetPhantom.exe"
$exe2 = "c:\Users\Lucky\Downloads\NetPhantom-main\NetPhantom-main\installers\windows\dist\NetPhantom_Setup.exe"

if (Test-Path $exe1) {
    Set-AuthenticodeSignature -FilePath $exe1 -Certificate $cert
    Write-Host "Signed $exe1"
}

if (Test-Path $exe2) {
    Set-AuthenticodeSignature -FilePath $exe2 -Certificate $cert
    Write-Host "Signed $exe2"
}

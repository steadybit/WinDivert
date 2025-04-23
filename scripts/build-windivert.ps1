# Move to project root directory before executing any operation
Set-Location -Path (Join-Path $PSScriptRoot "..")

if ($args.Count -eq 0) {
    $config = "Debug"
    $sign = "NoSign"
} elseif ($args.Count -eq 1) {
    $config = $args[0]
    $sign = "NoSign"
}else{
    $config = $args[0]
    $sign = $args[1] 
}

if($sign -match "Sign"){
    Write-Host "Creating self-signing certificate"
    $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=WinDivertTestCert" -KeyUsage DigitalSignature -FriendlyName "WinDivert Test Cert" -CertStoreLocation "Cert:\CurrentUser\My"
    Write-Output $cert
    Write-Host "Building $config driver using self-signing certificate"
    msbuild "sys\windivertdriver.vcxproj" /v:n /p:Configuration=$config /p:Platform=x64 /p:TestCertificate=$($cert.Thumbprint) /p:OutDir="..\output\x64\$config\"
}else{
    Write-Host "Building $config driver"
    msbuild "sys\windivertdriver.vcxproj" /v:n /p:Configuration=$config /p:Platform=x64 /p:OutDir="..\output\x64\$config\" /p:SignMode=Off
}

Write-Host "Building $config WinDivert DLL"
msbuild "dll\windivert.vcxproj" /v:n /p:Configuration=$config /p:Platform=x64 /p:OutDir="..\output\x64\$config\"

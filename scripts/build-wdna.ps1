# Move to project root directory before executing any operation
Set-Location -Path (Join-Path $PSScriptRoot "..")

if ($args.Count -eq 0) {
    $config = "Debug"
} else {
    $config = $args[0]
}

Write-Host "Building WDNA in $config configuratio"

msbuild "examples\wdna\wdna.vcxproj" /v:d /p:Configuration=$config /p:Platform=x64 /p:OutDir="..\..\output\x64\$config\"

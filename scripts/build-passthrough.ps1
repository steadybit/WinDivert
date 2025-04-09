Set-Location -Path (Join-Path $PSScriptRoot "..")

if ($args.Count -eq 0) {
    $config = "Debug"
} else {
    $config = $args[0]
}

Write-Host "Building 'Passthrough' in $config configuration"

msbuild "examples\passthru\passthru.vcxproj" /v:d /p:Configuration=$config /p:Platform=x64 /p:OutDir="..\..\output\x64\$config\"
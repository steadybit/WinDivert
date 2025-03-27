Set-Location -Path (Join-Path $PSScriptRoot "..")

if ($args.Count -eq 0) {
    $config = "Debug"
} else {
    $config = $args[0]
}

copy ".\sys\windivert64.inf" ".\output\x64\$config\"
Inf2Cat.exe /driver:".\output\x64\$config\" /os:10_NI_X64
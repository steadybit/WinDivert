msbuild dll\windivert.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\output\x64\Release\

msbuild examples\wdna\wdna.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\
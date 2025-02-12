:: msvc-build.bat
:: (C) 2019, all rights reserved,
::
:: This file is part of WinDivert.
::
:: WinDivert is free software: you can redistribute it and/or modify it under
:: the terms of the GNU Lesser General Public License as published by the
:: Free Software Foundation, either version 3 of the License, or (at your
:: option) any later version.
::
:: This program is distributed in the hope that it will be useful, but
:: WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
:: or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
:: License for more details.
::
:: You should have received a copy of the GNU Lesser General Public License
:: along with this program.  If not, see <http://www.gnu.org/licenses/>.
::
:: WinDivert is free software; you can redistribute it and/or modify it under
:: the terms of the GNU General Public License as published by the Free
:: Software Foundation; either version 2 of the License, or (at your option)
:: any later version.
:: 
:: This program is distributed in the hope that it will be useful, but
:: WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
:: or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
:: for more details.
:: 
:: You should have received a copy of the GNU General Public License along
:: with this program; if not, write to the Free Software Foundation, Inc., 51
:: Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

@echo off

msbuild sys\windivertdriver.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\output\x64\Release\

msbuild dll\windivert.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\output\x64\Release\

msbuild examples\flowtrack\flowtrack.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild examples\netdump\netdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild examples\netfilter\netfilter.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild examples\passthru\passthru.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild examples\socketdump\socketdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild examples\streamdump\streamdump.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild examples\webfilter\webfilter.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild examples\windivertctl\windivertctl.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\..\output\x64\Release\

msbuild test\test.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=..\output\x64\Release\


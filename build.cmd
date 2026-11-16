@echo off
rem Build Hashslinger.exe with the C# compiler that ships with Windows (.NET Framework 4.x).
rem No SDK or Visual Studio needed. The code is written to compile as C# 5.
set CSC=%windir%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" (echo csc.exe not found & exit /b 1)
"%CSC%" /nologo /optimize+ /unsafe /platform:x64 /target:exe /out:Hashslinger.exe /r:System.dll /r:System.Core.dll cs\*.cs
if errorlevel 1 exit /b 1
echo Built Hashslinger.exe. Run: Hashslinger.exe selftest

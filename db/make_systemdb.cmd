@rem this file is in the Public Domain
@echo off

SET SQL= %USERPROFILE%\vcpkg\installed\%native_vcpkg_platform%\tools\sqlite3.exe
if exist system.db del /f system.db
%SQL% -batch system.db < create_system_db.sql
for %%c in (*.csv) do echo %%c && echo .import "%%c" wordlist | %SQL% -batch -csv system.db

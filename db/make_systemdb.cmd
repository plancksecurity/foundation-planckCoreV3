@echo off

if exist system.db del /f system.db
sqlite3 -batch system.db < create_system_db.sql
for %%c in (*.csv) do echo %%c && echo .import "%%c" wordlist | sqlite3 -batch -csv system.db

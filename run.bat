@echo off
cd /d "%~dp0"
python db_search.py
if errorlevel 1 pause

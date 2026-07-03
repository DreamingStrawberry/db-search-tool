@echo off
cd /d "%~dp0"
pip install -q pyinstaller pyodbc psycopg2-binary oracledb cryptography
pyinstaller --noconfirm --clean --onefile --windowed --name DBSearch --icon icon.ico --add-data "icon.ico;." db_search.py
if errorlevel 1 exit /b 1
copy /y dist\DBSearch.exe DBSearch.exe >nul
echo OK: DBSearch.exe

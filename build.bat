@echo off
cd /d "%~dp0"
pip install -q pyinstaller pyodbc python-tds psycopg2-binary oracledb pymysql cryptography
pyinstaller --noconfirm --clean --onefile --windowed --name DBSearch --icon icon.ico --collect-submodules cryptography --collect-submodules pytds --collect-submodules pymysql --hidden-import pyodbc --add-data "icon.ico;." db_search.py
if errorlevel 1 exit /b 1
copy /y dist\DBSearch.exe DBSearch.exe >nul
echo OK: DBSearch.exe

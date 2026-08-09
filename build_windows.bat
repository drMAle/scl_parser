@echo off
setlocal

echo ========================================
echo SCL Analyzer - Windows Build
echo ========================================

echo.
echo [1/4] Creating virtual environment...
if not exist .venv (
    python -m venv .venv
)

echo.
echo [2/4] Activating virtual environment...
call .venv\Scripts\activate.bat

echo.
echo [3/4] Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [4/4] Building executable...
pyinstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --name SCLAnalyzer ^
    main.py

echo.
echo ========================================
echo Build completed.
echo Executable:
echo dist\SCLAnalyzer.exe
echo ========================================

pause


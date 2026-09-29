@echo off
echo ==============================================
echo  Compilazione Nukexe in corso...
echo ==============================================

REM Pulizia build precedenti
rmdir /s /q build dist 2>nul

pyinstaller --noconsole --onefile --name Nukexe ^
    --add-data "dashboard.html;." ^
    --add-data "nukexe.png;." ^
    --add-data "nukexe.ico;." ^
    --collect-submodules uvicorn ^
    --icon nukexe.ico ^
    --version-file=version.txt ^
    Nukexe.py

echo.
if exist "dist\Nukexe.exe" (
    echo ==============================================
    echo  [OK] Compilazione completata con successo!
    echo  Eseguibile disponibile in: dist\Nukexe.exe
    echo ==============================================
) else (
    echo [ERRORE] Compilazione fallita. Controlla i messaggi sopra.
)
pause
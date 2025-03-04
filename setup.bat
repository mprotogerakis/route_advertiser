@echo off
setlocal enabledelayedexpansion

set PYTHON_PATH=python
set REPO_URL=https://github.com/mprotogerakis/route_advertiser.git
set PROJECT_DIR=route_advertiser

:: Prüfen, ob Python existiert
where %PYTHON_PATH% >nul 2>nul
if %errorlevel% neq 0 (
    echo ? Python nicht gefunden! Versuche Standardpfad...
    set PYTHON_PATH=C:\Users\Michael Protogerakis\AppData\Local\Programs\Python\Python313\python.exe
)

where %PYTHON_PATH% >nul 2>nul
if %errorlevel% neq 0 (
    echo ? Python nicht im PATH! Installiere es oder setze den korrekten Pfad.
    exit /b 1
)

:: Prüfen, ob Git existiert
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo ? Git ist nicht installiert! Bitte installiere Git.
    exit /b 1
)

:: Repository klonen oder aktualisieren
if not exist %PROJECT_DIR% (
    echo ? Klone Repository von GitHub...
    git clone %REPO_URL%
) else (
    echo ? Repository existiert bereits. Ziehe neueste Änderungen...
    cd %PROJECT_DIR%
    git pull origin main
    cd ..
)

cd %PROJECT_DIR%

:: Alte venv löschen, falls defekt
if exist venv (
    echo ? Entferne alte virtuelle Umgebung...
    rmdir /s /q venv
)

:: Neue virtuelle Umgebung erstellen
echo ? Erstelle virtuelle Umgebung...
%PYTHON_PATH% -m venv venv

:: Prüfen, ob die venv-Skripte existieren
if not exist venv\Scripts\activate.bat (
    echo ? Fehler: Virtuelle Umgebung wurde nicht korrekt erstellt!
    exit /b 1
)

:: Virtuelle Umgebung aktivieren
echo ? Aktiviere virtuelle Umgebung...
call venv\Scripts\activate.bat

:: Aktualisiere pip
echo ? Aktualisiere pip...
%PYTHON_PATH% -m pip install --upgrade pip

:: Installiere Abhängigkeiten
if exist requirements.txt (
    echo ? Installiere benötigte Pakete...
    pip install -r requirements.txt
) else (
    echo ?? Keine requirements.txt gefunden!
)

echo ? Setup abgeschlossen! Um den Client zu starten:
echo ??  cd route_advertiser
echo ??  venv\Scripts\activate
echo ??  python client.py start

endlocal
pause
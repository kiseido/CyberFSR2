@echo off
setlocal

set "startTime=%TIME%"

set "origin=%cd%\"
set "buildPath=external\FidelityFX-FSR2\build"
set "slnDX12=FSR2_Sample_DX12.sln"
set "slnDX11=FSR2_Sample.sln"
set "slnVK=FSR2_Sample_VK.sln"

echo Current working directory: %origin%

REM Clear old artifacts
echo [%TIME%] Clearing old artifacts...
cd /d "%origin%%buildPath%"
if exist "DX11" (
    echo [%TIME%] Removing old DX11 artifacts...
    rd /s /q "DX11" > nul 2>&1
)
if exist "DX12" (
    echo [%TIME%] Removing old DX12 artifacts...
    rd /s /q "DX12" > nul 2>&1
)
if exist "VK" (
    echo [%TIME%] Removing old VK artifacts...
    rd /s /q "VK" > nul 2>&1
)

REM Regenerate artifacts
echo [%TIME%] Regenerating artifacts...
cd /d "%origin%%buildPath%"

echo [%TIME%] Doing GenerateSolutionsDX11.bat...
call GenerateSolutionDX11.bat > nul 2>&1

echo [%TIME%] Regenerating DX11 artifacts...
REM Build FSR2_Sample_DX11.sln
call :BuildSolution "%origin%%buildPath%\DX11\%slnDX11%" "Debug" "DX11"
call :BuildSolution "%origin%%buildPath%\DX11\%slnDX11%" "Release" "DX11"

echo [%TIME%] Doing GenerateSolutions.bat...
cd /d "%origin%%buildPath%"
call GenerateSolutions.bat > nul 2>&1

echo [%TIME%] Regenerating DX12 artifacts...
REM Build FSR2_Sample_DX12.sln
call :BuildSolution "%origin%%buildPath%\DX12\%slnDX12%" "Debug" "DX12"
call :BuildSolution "%origin%%buildPath%\DX12\%slnDX12%" "Release" "DX12"

echo [%TIME%] Regenerating VK artifacts...
REM Build FSR2_Sample_VK.sln
call :BuildSolution "%origin%%buildPath%\VK\%slnVK%" "Debug" "VK"
call :BuildSolution "%origin%%buildPath%\VK\%slnVK%" "Release" "VK"

cd /d "%origin%"
goto :endofBuildFSR2

REM Function to build a solution file
:BuildSolution
set "solutionPath=%~1"
set "configuration=%~2"
if exist "%solutionPath%" (
    echo [%TIME%] Building %solutionPath%...
    cd /d "%origin%%buildPath%\%~3"
    MSBUILD.exe "%solutionPath%" /t:Build /p:Configuration=%configuration%  > nul 2>&1
) else (
    echo [%TIME%] %solutionPath% not found. Skipping build.
)
exit /b

:endofBuildFSR2

REM Echo the starting time again as the ending time
echo Starting time: %startTime%
echo Ending time: %TIME%

endlocal

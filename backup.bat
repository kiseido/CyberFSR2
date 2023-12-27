@ECHO OFF
SETLOCAL

REM Change these folder names as necessary
SET SourceFolder=PoCOverlay
SET BackupFolder=..\Backup_%DATE:/=%

REM Create a backup folder
ECHO Creating backup folder...
IF NOT EXIST "%BackupFolder%" (
    MKDIR "%BackupFolder%"
)

REM Copy all loose files from the PoCOverlay folder to the backup folder
ECHO Copying files to backup folder...
XCOPY "%SourceFolder%\*" "%BackupFolder%" /I /Q /Y

REM Check if the copy was successful
IF ERRORLEVEL 1 (
    ECHO Error occurred during backup. Exiting...
    EXIT /B 1
)

REM Create and switch to a new branch
ECHO Creating a new branch...
git checkout -b new-branch-name

REM If error, pause and exit
IF ERRORLEVEL 1 PAUSE & EXIT

REM Add all changes to git
ECHO Adding changes to the new branch...
git add .

REM If error, pause and exit
IF ERRORLEVEL 1 PAUSE & EXIT

REM Commit changes
ECHO Committing changes...
git commit -m "Your commit message"

REM If error, pause and exit
IF ERRORLEVEL 1 PAUSE & EXIT

REM Push the new branch to remote
ECHO Pushing new branch to remote...
git push origin new-branch-name

REM If error, pause and exit
IF ERRORLEVEL 1 PAUSE & EXIT

ECHO Script completed successfully!
ENDLOCAL

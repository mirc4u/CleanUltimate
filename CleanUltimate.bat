@echo off
color 9
title Clean Ultimate
set version=0.9
cd %tmp%
setlocal EnableDelayedExpansion
::Text Color Red
set col1=[91m
::Highlight Color Blue
set col2=[94m

) else (
::Text Color White
set col1=[97m
::Highlight Color Red
set col2=[31m

:checkupdate
color 9
curl -g -k -L -# -o "%tmp%\latestVersion.bat" "https://raw.githubusercontent.com/Mircau123/CleanUltimate/main/Clean" >nul 2>&1
call "%tmp%\latestVersion.bat"
if "%DevBuild%" neq "Yes" if "%Version%" lss "!latestVersion!" (cls
	echo.
	echo             %col1%CleanUltimate isn't updated. Do you want to update?%col2%
	echo.
	choice /c:"YN" /n /m "                      %BS%                      [Y] Yes  [N] No"
	if !errorlevel! equ 1 (
		curl -L -o "%~s0" "https://github.com/UnLovedCookie/EchoX/releases/latest/download/EchoX.bat" >nul 2>&1
		call "%~s0"
	)
)

:loading
cls
echo.
echo    ______________                        _____  ________________                  _____      
echo    __  ____/__  /__________ _______      __  / / /__  /_  /___(_)______ _________ __  /_____ 
echo    _  /    __  /_  _ \  __ `/_  __ \     _  / / /__  /_  __/_  /__  __ `__ \  __ `/  __/  _ \
echo    / /___  _  / /  __/ /_/ /_  / / /     / /_/ / _  / / /_ _  / _  / / / / / /_/ // /_ /  __/
echo    \____/  /_/  \___/\__,_/ /_/ /_/      \____/  /_/  \__/ /_/  /_/ /_/ /_/\__,_/ \__/ \___/ 
echo.
echo                                   %col1%Loading Scripts [...]%col1%
echo.
timeout /t 1 /nobreak>nul
cls
color 9
echo.
echo    ______________                        _____  ________________                  _____      
echo    __  ____/__  /__________ _______      __  / / /__  /_  /___(_)______ _________ __  /_____ 
echo    _  /    __  /_  _ \  __ `/_  __ \     _  / / /__  /_  __/_  /__  __ `__ \  __ `/  __/  _ \
echo    / /___  _  / /  __/ /_/ /_  / / /     / /_/ / _  / / /_ _  / _  / / / / / /_/ // /_ /  __/
echo    \____/  /_/  \___/\__,_/ /_/ /_/      \____/  /_/  \__/ /_/  /_/ /_/ /_/\__,_/ \__/ \___/ 
echo.
echo                                   %col1%Loading Settings [...]%col1%                                
echo.
timeout /t 1 /nobreak>nul
cls

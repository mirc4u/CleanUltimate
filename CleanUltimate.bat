@echo off
color 9
title Clean Ultimate
set version=1.9
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

::Get Admin Rights
rmdir %SystemDrive%\Windows\system32\adminrightstest >nul 2>&1
mkdir %SystemDrive%\Windows\system32\adminrightstest >nul 2>&1
if %errorlevel% neq 0 (
powershell -NoProfile -NonInteractive -Command start -verb runas "'%~s0'" >nul 2>&1
if !errorlevel! equ 0 exit /b
echo.
echo             %col2%CleanUltimate is not running as Admin!
echo      Optimization did not work correctly. Continue anyway?%col1%
echo.
choice /c:"CQ" /n /m "%BS%               [C] Continue  [Q] Quit" & if !errorlevel! equ 2 exit /b
)

:loading
cls
color 9
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
color 9
echo.
echo    ______________                        _____  ________________                  _____      
echo    __  ____/__  /__________ _______      __  / / /__  /_  /___(_)______ _________ __  /_____ 
echo    _  /    __  /_  _ \  __ `/_  __ \     _  / / /__  /_  __/_  /__  __ `__ \  __ `/  __/  _ \
echo    / /___  _  / /  __/ /_/ /_  / / /     / /_/ / _  / / /_ _  / _  / / / / / /_/ // /_ /  __/
echo    \____/  /_/  \___/\__,_/ /_/ /_/      \____/  /_/  \__/ /_/  /_/ /_/ /_/\__,_/ \__/ \___/ 
echo.

:checkupdate
color 9
curl -g -k -L -# -o "%tmp%\latestVersion.bat" "https://raw.githubusercontent.com/Mircau123/CleanUltimate/main/Clean" >nul 2>&1
call "%tmp%\latestVersion.bat"
if "%Version%" lss "!latestVersion!" (

	echo.
	echo                      %col1%CleanUltimate isn't updated. Do you want to update?%col2%
	echo.
	choice /c:"YN" /n /m "                      %BS%                      [Y] Yes  [N] No"
	if !errorlevel! equ 1 (
		curl -L -o "%~s0" "colocar link dps" >nul 2>&1
		call "%~s0"
	)
)

:main
cls
title CleanUltimate
color 9
echo.
echo    ______________                        _____  ________________                  _____      
echo    __  ____/__  /__________ _______      __  / / /__  /_  /___(_)______ _________ __  /_____ 
echo    _  /    __  /_  _ \  __ `/_  __ \     _  / / /__  /_  __/_  /__  __ `__ \  __ `/  __/  _ \
echo    / /___  _  / /  __/ /_/ /_  / / /     / /_/ / _  / / /_ _  / _  / / / / / /_/ // /_ /  __/
echo    \____/  /_/  \___/\__,_/ /_/ /_/      \____/  /_/  \__/ /_/  /_/ /_/ /_/\__,_/ \__/ \___/ 
echo.
echo                            %col1%1 [Optimizer]    2 [Apps]    3 [Config]%col1%                               
echo.

set /p main= Select:

if %main% equ 1 goto optimizer
if %main% equ 2 goto apps
if %main% equ 3 goto config
echo.
echo    %col2%Option not found. Press any key to try again . . .%col1%
echo.
pause>nul
goto main

:config
cls
color 9
echo.
echo    ______________                        _____  ________________                  _____      
echo    __  ____/__  /__________ _______      __  / / /__  /_  /___(_)______ _________ __  /_____ 
echo    _  /    __  /_  _ \  __ `/_  __ \     _  / / /__  /_  __/_  /__  __ `__ \  __ `/  __/  _ \
echo    / /___  _  / /  __/ /_/ /_  / / /     / /_/ / _  / / /_ _  / _  / / / / / /_/ // /_ /  __/
echo    \____/  /_/  \___/\__,_/ /_/ /_/      \____/  /_/  \__/ /_/  /_/ /_/ /_/\__,_/ \__/ \___/                      
echo.
echo                       %col1%1 [Update]    2 [Discord]    3 [Back]%version%%col2% 
echo.
set /p main= Select:

if %main% equ 1 goto update
if %main% equ 2 goto discord
if %main% equ 3 goto main
echo.
echo    %col2%Option not found. Press any key to try again . . .%col1%
echo.
pause>nul
goto config

:discord
start https://discord.gg/4sN8rz867W
goto config

:apps
msg * Em breve!
goto main
cls
color 9
echo.
echo    ______________                        _____  ________________                  _____      
echo    __  ____/__  /__________ _______      __  / / /__  /_  /___(_)______ _________ __  /_____ 
echo    _  /    __  /_  _ \  __ `/_  __ \     _  / / /__  /_  __/_  /__  __ `__ \  __ `/  __/  _ \
echo    / /___  _  / /  __/ /_/ /_  / / /     / /_/ / _  / / /_ _  / _  / / / / / /_/ // /_ /  __/
echo    \____/  /_/  \___/\__,_/ /_/ /_/      \____/  /_/  \__/ /_/  /_/ /_/ /_/\__,_/ \__/ \___/ 
echo.

:optimizer
cls
color 9
echo.
echo    ______________                        _____  ________________                  _____      
echo    __  ____/__  /__________ _______      __  / / /__  /_  /___(_)______ _________ __  /_____ 
echo    _  /    __  /_  _ \  __ `/_  __ \     _  / / /__  /_  __/_  /__  __ `__ \  __ `/  __/  _ \
echo    / /___  _  / /  __/ /_/ /_  / / /     / /_/ / _  / / /_ _  / _  / / / / / /_/ // /_ /  __/
echo    \____/  /_/  \___/\__,_/ /_/ /_/      \____/  /_/  \__/ /_/  /_/ /_/ /_/\__,_/ \__/ \___/ 
echo.
echo
title Process . . . 0%%%
powercfg.exe /hibernate off
sc config wuauserv start= disabled
sc stop wuauserv
sc stop SysMain
sc config SysMain start= disabled
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable
schtasks /Change /TN "Microsoft\Office\Office Automatic Updates 2.0" /Disable
schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /Disable
schtasks /Change /TN "Microsoft\Office\Office Feature Updates" /Disable
schtasks /Change /TN "Microsoft\Office\Office Feature Updates Logon" /Disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "MicrosoftEdgeUpdateTaskMachineCore" /Disable
schtasks /Change /TN "MicrosoftEdgeUpdateTaskMachineUA" /Disable
title Process . . . 14%%%
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d 2000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d 8 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 00000002 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 00000003 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9032078010000000 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM " /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewAlphaSelect" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DragFullWindows" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /V "AlwaysHibernateThumbnails" /T REG_DWORD /D 0 /F
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\DWM" /V "EnableAeroPeek" /T REG_DWORD /D 0 /F
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /V "AppCaptureEnabled" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /V "GameDVR_Enabled" /T REG_DWORD /D 0 /F
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked" /v "ShowDesktopButton" /t REG_DWORD /d "54" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked" /v "ShowDesktopButton" /t REG_DWORD /d "55" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "SecondLevelDataCache" /t REG_DWORD /D 1024 /F
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet001\Control\Session Manager\Memory Management" /V "SecondLevelDataCache" /t REG_DWORD /D 1024 /F
powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
title Process . . . 28%%%
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change disk-timeout-ac 0
powercfg /change disk-timeout-dc 0
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
powercfg -SETACVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -SETDCVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 3
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 0 /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f
Reg Add "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoColorization /t REG_DWORD /d 0 /f
powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
for /f %%a in ('wmic cpu get L2CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l2c=%%a
    set /a sum1=%%a
) 
for /f %%a in ('wmic cpu get L3CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l3c=%%a
    set /a sum2=%%a
) 
del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp 
md c:\windows\temp
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
rd /s /q c:\windows\prefetch\
powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
md c:\windows\prefetch\
rd /s /q C:\$Recycle.bin
sc config wuauserv start= disabled
sc stop wuauserv
del *.log /a /s /q /f
del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q C:\Windows\SoftwareDistribution\Download
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
del c:\WIN386.SWP
net stop wuauserv
net stop UsoSvc
rd /s /q C:\Windows\SoftwareDistribution
md C:\Windows\SoftwareDistribution
bcdedit /deletevalue useplatformclock
bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
bcdedit /timeout 0
bcdedit /set nx optout
title Process . . . 59%%%
bcdedit /set bootux disabled
bcdedit /set bootmenupolicy standard
bcdedit /set hypervisorlaunchtype off
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set quietboot yes
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {globalsettings} custom:16000068 true
PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxGameCallableUI* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxLive* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
bcdedit /set useplatformclock No 
bcdedit /set allowedinmemorysettings 0
bcdedit /deletevalue useplatformtick 
title Process . . . 70%%%
bcdedit /set tscsyncpolicy Enhanced
bcdedit /set disabledynamictick Yes
bcdedit /set x2apicpolicy Enable
bcdedit /set perfmem 0
bcdedit /set uselegacyapicmode No 
bcdedit /set MSI Default
bcdedit /set debug No
bcdedit /set useplatformclock No 
bcdedit /set allowedinmemorysettings 0
bcdedit /set useplatformtick Yes 
bcdedit /set tscsyncpolicy Legacy
bcdedit /set disabledynamictick Yes
bcdedit /set x2apicpolicy No
bcdedit /set perfmem 0
bcdedit /set uselegacyapicmode No 
bcdedit /set MSI Default
bcdedit /set debug No
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
bcdedit /deletevalue useplatformclock
bcdedit /set tscyncpolicy enhanced
bcdedit /set bootux disabled
bcdedit /set nx alwaysoff
bcdedit /set disabledynamictick yes
bcdedit /set hypervisorlaunchtype off
bcdedit /set quietboot yes
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set useplatformclock no 
bcdedit /set useplatformtick yes
bcdedit /deletevalue useplatformclock
bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
bcdedit /timeout 0
bcdedit /set nx optout
bcdedit /set bootux disabled
bcdedit /set bootmenupolicy standard
bcdedit /set hypervisorlaunchtype off
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set quietboot yes
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {globalsettings} custom:16000068 true
bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0x0
title Process . . . 87%%%
bcdedit /set isolatedcontext No
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
bcdedit /set tscsyncpolicy legacy
/s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
del c:\WIN386.SWP
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
for /f %%a in ('wmic cpu get L2CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l2c=%%a
    set /a sum1=%%a
) 
for /f %%a in ('wmic cpu get L3CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l3c=%%a
    set /a sum2=%%a
) 
reg add "hklm\system\controlset001\control\session manager\memory management" /v "secondleveldatacache" /t reg_dword /d "%sum1%" /f
reg add "hklm\system\controlset001\control\session manager\memory management" /v "thirdleveldatacache" /t reg_dword /d "%sum2%" /f
reg add "hklm\system\controlset001\control\session manager\memory management" /v "pagingfiles" /t reg_multi_sz /d "c:\pagefile.sys 0 0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "contigfileallocsize" /t reg_dword /d "1536" /f
reg add "hklm\system\controlset001\control\filesystem" /v "disabledeletenotification" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "dontverifyrandomdrivers" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "filenamecache" /t reg_dword /d "1024" /f
reg add "hklm\system\controlset001\control\filesystem" /v "longpathsenabled" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsallowextendedcharacter8dot3rename" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsbugcheckoncorrupt" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsdisable8dot3namecreation" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsdisablecompression" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsdisableencryption" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsencryptpagingfile" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsmemoryusage" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsmftzonereservation" /t reg_dword /d "4" /f
reg add "hklm\system\controlset001\control\filesystem" /v "pathcache" /t reg_dword /d "128" /f
reg add "hklm\system\controlset001\control\filesystem" /v "refsdisablelastaccessupdate" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "udfssoftwaredefectmanagement" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "win31filesystem" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "contigfileallocsize" /t reg_dword /d "1536" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "disabledeletenotification" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "dontverifyrandomdrivers" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "filenamecache" /t reg_dword /d "1024" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "longpathsenabled" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsallowextendedcharacter8dot3rename" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsbugcheckoncorrupt" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsdisable8dot3namecreation" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsdisablecompression" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsdisableencryption" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsencryptpagingfile" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsmemoryusage" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsmftzonereservation" /t reg_dword /d "3" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "pathcache" /t reg_dword /d "128" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "refsdisablelastaccessupdate" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "udfssoftwaredefectmanagement" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "win31filesystem" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\executive" /v "additionalcriticalworkerthreads" /t reg_dword /d "00000016" /f
reg add "hklm\system\currentcontrolset\control\session manager\executive" /v "additionaldelayedworkerthreads" /t reg_dword /d "00000016" /f
reg add "hklm\system\currentcontrolset\control\session manager\i/o system" /v "countoperations" /t reg_dword /d "00000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "clearpagefileatshutdown" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "featuresettingsoverride" reg_dword /d "00000003" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "featuresettingsoverridemask" reg_dword /d "00000003" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "iopagelocklimit" /t reg_dword /d "08000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "largesystemcache" /t reg_dword /d "00000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "systempages" /t reg_dword /d "4294967295" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "disablepagingexecutive" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "iopagelocklimit" /t reg_dword /d "16710656" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "largesystemcache" /t reg_dword /d "00000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enableboottrace" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enableprefetcher" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enablesuperfetch" /t reg_dword /d "0" /f
for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%a
reg add "hklm\system\currentcontrolset\control" /v "svchostsplitthresholdinkb" /t reg_dword /d "%ram%" /f
title Process . . . 100%%%
msg * Boost Finish! Restart PC.
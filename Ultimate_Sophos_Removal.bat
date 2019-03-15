:: ---------------------- PREREQUISITES --------------------------

echo Ready to run this script?
pause

@setlocal EnableDelayedExpansion
:: Script cannot be run on servers
FOR /F "TOKENS=1,* DELIMS==" %%u IN ('WMIC OS GET CAPTION /VALUE') DO IF /I "%%u"=="Caption" SET vers=%%v
ECHO.%vers% | FIND /I "Microsoft Windows Server">Nul && (echo You cannot run this script on a server&pause&exit)
@setlocal DisableDelayedExpansion

:: Script must be run with elevation
openfiles>nul 2>&1
if %errorlevel% EQU 0 goto ElevatedTrue
echo Script NOT executed with administrative elevation
pause
exit
:ElevatedTrue
echo Script executed with administrative elevation



:: ----------------------- MAIN INDEX ----------------------------
:: This script is constructed to apply an order of operation for Sophos components and services as defined by Sophos company, as best as possible, from https://community.sophos.com/kb/en-us/122126 and https://community.sophos.com/kb/en-us/109668 . The application of this OOO in this script is not 100% perfect, but I tried my best to match the words of the Sophos company. Here is the OOO list that I have assembled based on these resources and some educated guesses (some Sophos products are missing from this list because I was unable to find resources on them):
::	Sophos Patch Agent
::	Sophos Compliance Agent / NAC / Network Access Compliance
::	Sophos Network Threat Protection / NTP / Endpoint / Server
::	Sophos System Protection / SSP
::	Sophos Client Firewall / SCF
::	Sophos Endpoint Firewall / Endpoint / Server
::	Sophos Anti-Virus Endpoint
::	Sophos Anti-Virus Server
::	Sophos Anti-Virus / SAV
::	Sophos Exploit Prevention / SEP
::	Sophos Remote Management System / RMS
::	Sophos Health / Endpoint / Server
::	Sophos Diagnostic Utility / Endpoint / Server
::	Sophos Management Communications System / MCS / Server
::	Sophos Management Communications System Endpoint
::	Sophos Management Console
::	Sophos Management Server
::	Sophos Management Database
::	Sophos [MCS?] Heartbeat
::	Sophos Endpoint Self Help / Endpoint / Server
::	Sophos Lockdown
::	Sophos File Scanner / Endpoint / Server
::	Sophos Standalone Engine / Endpoint / Server
::	Sophos ML Engine
::	Sophos Endpoint
::	Sophos Endpoint Agent
::	Sophos Clean / Endpoint / Server
::	Sophos AutoUpdate XG / Endpoint / Server
::	Sophos AutoUpdate / SAU
::	Sophos Endpoint Defense / SED / Endpoint / Server
::	HitmanPro / HMPA managed
::	HitmanPro
::	Others - Sophos Message Router
::	Others - Sophos Cache Manager / Update Manager
::	Others - Sophos Certification Manager
::	Others - Sophos Cloud AD Sync Utility
::	Others - Sophos Data Recorder
::	Others - Sophos File Integrity Monitoring
::	Others - Sophos Management Host
::	Others - Sophos Management Service
::	Others - Sophos Patch Endpoint Communicator
::	Others - Sophos Patch Endpoint Orchestrator
::	Others - Sophos Patch Server Communicator
::	Others - Sophos Policy Evaluation Service
::	Others - Sophos PureMessage
::	Others - Sophos PureMessage Web Agent
::	Others - Sophos PureMessage Running Object Table (ROT)
::	Others - Sophos PureMessage Content Extractor
::	Others - Sophos PureMessage Watchdog Agent
::	Others - Sophos PureMessage Scanner
::	Others - Sophos Encryption For Cloud Storage
::	Others - Sophos Central AD Sync Utility
::	Others - Sophos Virus Removal Tool
::	Others - Unknown



:: This script is not specifically targetting HitmanPro but includes some entries because of someone's Sophos removal script



:: Here is the general procedure we are following for removal of Sophos:
::	1.	Disable, gracefully stop, and forcefully stop "Sophos AutoUpdate Service" service (as advised at ttps://community.sophos.com/kb/en-us/109668)
::	2.	Perform graceful Sophos MSI/EXE uninstalls to allow the product the opportunity to properly remove itself
::	3.	Set all Sophos services to disabled
::	4.	Stop all Sophos services gracefully
::	5.	Kill all Sophos services by force
::	6.	Set all Sophos driver services to disabled
::	7.	Stop all Sophos driver services gracefully
::	8.	Kill all Sophos driver services by force
::	9.	Uninstall all Sophos driver services via INF files
::	10. Kill all Sophos processes by force
::	11. Repeat steps 1-10 (we attempted graceful uninstall outright, this time we will retry gracefull uninstall but with all services and processes stopped and some drivers unhooked. We haven't deleted anything yet!)
::	12. Delete all Sophos services
::	13. Delete all Sophos driver services
::	14. Unregister EXEs to known Sophos files (/UnRegServer and -Uninstall methods)
::	15.	Unregister DLLs to known Sophos files (REGSVR32 method)
::	16. Kill all Sophos processes by force
::	17. Delete all Sophos registry keys and values
::	18. Nuke all Sophos folders and files from orbit
::	19. Repeat steps 1-18 (if something still lingers on the system by this point in time then there is a possibility that rerunning all the steps one last time will annihilate them. Ultimately, a reboot will be necessary to confirm that the system comes back online and to allow PendingFileRenameOperations to do its thing for remaining files)



:: This script was put together through extremely thorough research and analysis of/using:
::	-	SysInternals Autoruns, Process Explorer, and Process Monitor
::	-	Search Everything
::	-	RevoUninstaller Pro install/uninstall logs
::	-	MSI GUID, Service Name, Service Display Name, Install Path, and Uninstall String search from RMM system of 11000 agents
::	-	Probably more than 10 different Sophos removal scripts found via Googling
::	-	More than 40 hours of time



set TryAgain=TRUE
set OneLastTime=TRUE
:TryAgain
call :proxy Prerequisites
call :proxy Uninstall
call :proxy Services
if "%TryAgain%"=="TRUE" (set TryAgain=FALSE&goto :TryAgain)
:: Uncomment the next two lines + the 'pause' under labels :proxy and :proxytwo to aide with debugging
::echo You should have seen MSI stuff happen twice
::pause
call :proxytwo Unregister
call :proxytwo Deletion
:: The purpose of OneLastTime is to do one last round for the absolutely stubborn files
if "%OneLastTime%"=="TRUE" (set OneLastTime=FALSE&goto :TryAgain)

echo Script is at the end of the line and has finished
pause
exit



:: ---------------------------- CHAPTERS -----------------------------
:Prerequisites
:: The first order of operation is to stop and cripple the AutoUpdate service as instructed at https://community.sophos.com/kb/en-us/109668
:: Sophos AutoUpdate Service
sc config "Sophos AutoUpdate Service" start= disabled
net stop "Sophos AutoUpdate Service"
taskkill /T /F /IM "ALsvc.exe"
sc delete "Sophos AutoUpdate Service"
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sophos AutoUpdate Service" /f
exit /b 0



:Uninstall
:: The second thing we are going to do is try to uninstall all Sophos products gracefully and let them complete most of the removal work.
:: The sources of some GUIDs (not in any particular order):
::	(1) https://community.sophos.com/products/endpoint-security-control/f/sophos-endpoint-software/93514/endpoint-agent-installation/338867?pi2147=246
::	(2) https://www.itninja.com/software/sophos/anti-virus/7-201
::	(3) https://kc.mcafee.com/corporate/index?page=content&id=KB85522&locale=en_SG&viewlocale=en_SG
::	(4) https://gist.github.com/Coopeh/8470068
::	(5) https://rmccurdy.com/scripts/SOSO.txt
::	(6) Personally examining a virtual machine with Sophos Endpoint Agent installed using tools RevoUninstaller, Autoruns, Everything, Process Explorer
::	(7) And scripts written by others

:: Sophos Patch Agent
call :msiexec "{2FB80981-C6B6-4FCA-BC65-24437DF4C8CB}"
call :msiexec "{29006785-9EF7-4E84-ABE8-6244D12E7909}"
call :msiexec "{391530CF-3500-404D-867C-42514304917A}"
call :msiexec "{5565E71F-091B-42B8-8514-7E8944860BFD}"

:: Sophos Compliance Agent / NAC / Network Access Compliance
call :msiexec "{486FEABF-70EB-48C1-9C35-700B74A8EBE6}"
call :msiexec "{8BCFF7E3-E241-4230-BB5D-A6676E840F65}"
call :msiexec "{79406B81-26C4-4EAA-8CE2-5637B3279AC2}"
call :msiexec "{53613148-723B-4EF2-B45E-21F2BE0C0DB3}"
call :msiexec "{1A7EE8FF-391D-4030-8021-5F560189B87F}"
call :msiexec "{8BD17D77-227B-4CF6-BC9A-4304F569D8E9}"

:: Sophos Network Threat Protection / NTP / Endpoint / Server
call :msiexec "{604350BF-BE9A-4F79-B0EB-B1C22D889E2D}"
call :msiexec "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\ntp64\Sophos Network Threat Protection.msi"
call :msiexec "{66967E5F-43E8-4402-87A4-04685EE5C2CB}"

:: Sophos System Protection / SSP
call :msiexec "{934BEF80-B9D1-4A86-8B42-D8A6716A8D27}"
call :msiexec "{1093B57D-A613-47F3-90CF-0FD5C5DCFFE6}"

:: Sophos Client Firewall / SCF
call :msiexec "{12C00299-B8B4-40D3-9663-66ABEA3198AB}"
call :msiexec "{17071117-5BB2-4737-B05B-C5FABD367313}"

:: Sophos Endpoint Firewall / Endpoint / Server
call :msiexec "{2831282D-8519-4910-B339-2302840ABEF3}"
call :msiexec "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\efw64\Sophos Endpoint Firewall.msi"

::	Sophos Anti-Virus Endpoint
call :msiexec "{8123193C-9000-4EEB-B28A-E74E779759FA}"
call :msiexec "{36333618-1CE1-4EF2-8FFD-7F17394891CE}"
call :msiexec "{DFDA2077-95D0-4C5F-ACE7-41DA16639255}"
call :msiexec "{CA3CE456-B2D9-4812-8C69-17D6980432EF}"
call :msiexec "{CA524364-D9C5-4804-92DE-2800BDAC1AA4}"
call :msiexec "{3B998572-90A5-4D61-9022-00B288DD755D}"
call :msiexec "{4BAF6F55-FFE4-4A3A-8367-CC2EBB0F11C3}"
call :msiexec "{BA8752FE-75E5-43DD-9913-23509EFEB409}"
call :msiexec "{034759DA-E21A-4795-BFB3-C66D17FAD183}"
call :msiexec "{9ACB414D-9347-40B6-A453-5EFB2DB59DFA}"
::	Sophos Anti-Virus Server
call :msiexec "{72E30858-FC95-4C87-A697-670081EBF065}"
call :msiexec "{2519A41E-5D7C-429B-B2DB-1E943927CB3D}"
call :msiexec "{6654537D-935E-41C0-A18A-C55C2BF77B7E}"
:: Sophos Anti-Virus / SAV
call :msiexec "{6CA90A07-433B-4859-A785-006771D72109}"
call :msiexec "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\Sophos Anti-Virus.msi"
call :msiexec "{09C6BF52-6DBA-4A97-9939-B6C24E4738BF}"
call :msiexec "{09863DA9-7A9B-4430-9561-E04D178D7017}"
call :msiexec "{23E4E25E-E963-4C62-A18A-49C73AA3F963}"
call :msiexec "{65323B2D-83D4-470D-A209-D769DB30BBDB}"
call :msiexec "{C4EDC7DA-3AF8-4E99-ACAC-4C1A70F88CFB}"
call :msiexec "{D929B3B5-56C6-46CC-B3A3-A1A784CBB8E4}"

:: Sophos Exploit Prevention / SEP

:: Sophos Remote Management System / RMS
call :msiexec "{FED1005D-CBC8-45D5-A288-FFC7BB304121}"
call :msiexec "{FF11005D-CBC8-45D5-A288-25C7BB304121}"

:: Sophos Health / Endpoint / Server
call :msiexec "{E44AF5E6-7D11-4BDF-BEA8-AA7AE5FE6745}"
call :msiexec "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\shs\Sophos Health.msi"
call :msiexec "{A5CCEEF1-B6A7-4EB4-A826-267996A62A9E}"
call :msiexec "{D5BC54B8-1DA1-44F4-AE6F-86E05CDB0B44}"

:: Sophos Diagnostic Utility / Endpoint / Server
call :msiexec "{4627F5A1-E85A-4394-9DB3-875DF83AF6C2}"
call :msiexec "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sdu\Sophos Diagnostic Utility.msi"
:: "C:\Program Files (x86)\Sophos\Sophos Diagnostic Utility\setup.exe" remove
:: "C:\Program Files\Sophos\Sophos Diagnostic Utility\setup.exe" remove

:: Sophos Management Communications System / MCS / Server
call :msiexec "{A1DC5EF8-DD20-45E8-ABBD-F529A24D477B}"
call :msiexec "{1FFD3F20-5D24-4C9A-B9F6-A207A53CF179}"
call :msiexec "{D875F30C-B469-4998-9A08-FE145DD5DC1A}"
call :msiexec "{2C14E1A2-C4EB-466E-8374-81286D723D3A}"
:: Sophos Management Communications System Endpoint
"C:\Program Files\Sophos\Management Communication System\Endpoint\uninstall.exe" /uninstall /quiet
"C:\Program Files\Sophos\Management Communications System\Endpoint\uninstall.exe" /uninstall /quiet
"C:\Program Files (x86)\Sophos\Management Communication System\Endpoint\uninstall.exe" /uninstall /quiet
"C:\Program Files (x86)\Sophos\Management Communications System\Endpoint\uninstall.exe" /uninstall /quiet
:: Sophos Management Console
call :msiexec "{6D313E00-539A-4EDC-913B-0B1B349D1860}"
call :msiexec "{FC2876E5-3698-4534-A126-52792C4F0350}"
:: Sophos Management Server
call :msiexec "{9BCC5C9E-94B6-40CA-A025-2A33C78256C6}"
call :msiexec "{E9366D3F-ED09-42D1-BAFF-1EF2E3BF8A37}"
:: Sophos Management Database
call :msiexec "{8A911FCC-F927-4CEA-8B0B-C72BEFEA1034}"
call :msiexec "{E3C70B2C-0549-4F4C-87BE-B3D0EBDDAF26}"

:: Sophos [MCS?] Heartbeat
call :msiexec "{DFFA9361-3625-4219-82C2-9EF011E433B1}"

:: Sophos Endpoint Self Help / Endpoint / Server
call :msiexec "{9F69FA12-E3FE-4754-B7E3-B4DEEC8F6B5D}"
call :msiexec "{4EFCDD15-24A2-4D89-84A4-857D1BF68FA8}"
call :msiexec "{BB36D9C2-6AE5-4AB2-BC91-ECD247092BD8}"

:: Sophos Lockdown
call :msiexec "{77F92E90-ED4F-4CFF-8F60-3E3E4AEB705C}"

:: Sophos File Scanner / Endpoint / Server
"C:\Program Files\Sophos\Sophos File Scanner\Uninstall.exe"
"C:\Program Files (x86)\Sophos\Sophos File Scanner\Uninstall.exe"

:: Sophos Standalone Engine / Endpoint / Server
"C:\Program Files\Sophos\Sophos Standalone Engine\uninstall.exe"
"C:\Program Files (x86)\Sophos\Sophos Standalone Engine\uninstall.exe"

:: Sophos ML Engine
"C:\Program Files\Sophos\Sophos ML Engine\uninstall.exe"
"C:\Program Files (x86)\Sophos\Sophos ML Engine\uninstall.exe"

:: Sophos Endpoint
call :msiexec "{D29542AE-287C-42E4-AB28-3858E13C1A3E}"
:: Sophos Endpoint Agent
call :msiexec "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\ui64\Sophos UI.msi"
:: This pops up a GUI message + the message may be "The computer must be restarted before Sophos Endpoint Agent can be uninstalled."
::"C:\Program Files\Sophos\Sophos Endpoint Agent\uninstallgui.exe"
::"C:\Program Files (x86)\Sophos\Sophos Endpoint Agent\uninstallgui.exe"
:: This is better! If we temporarily remove PendingFileRenameOperations AND use uninstallcli.exe, no GUI + removal succeeds!
(reg copy "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" "HKLM\SYSTEM\CurrentControlSet\Control\_TMP_SMGR")&&((for /f "tokens=1" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\_TMP_SMGR" ^| find /V "PendingFileRenameOperations" ^| find /V "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SYSTEM\CurrentControlSet\Control\_TMP_SMGR" /v "%%~a" /f))&reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v PendingFileRenameOperations /f)||(echo Could not copy registry key)
"C:\Program Files\Sophos\Sophos Endpoint Agent\uninstallcli.exe"
"C:\Program Files (x86)\Sophos\Sophos Endpoint Agent\uninstallcli.exe"
reg copy "HKLM\SYSTEM\CurrentControlSet\Control\_TMP_SMGR" "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\_TMP_SMGR" /f

:: Sophos Clean / Endpoint / Server
"C:\Program Files\Sophos\Clean\uninstall.exe"
"C:\Program Files (x86)\Sophos\Clean\uninstall.exe"

:: Sophos AutoUpdate XG / Endpoint / Server

:: Sophos AutoUpdate / SAU
call :msiexec "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sau\Sophos AutoUpdate.msi"
call :msiexec "{72E136F7-3751-422E-AC7A-1B2E46391909}"
call :msiexec "{7CD26A0C-9B59-4E84-B5EE-B386B2F7AA16}"
call :msiexec "{BCF53039-A7FC-4C79-A3E3-437AE28FD918}"
call :msiexec "{9D1B8594-5DD2-4CDC-A5BD-98E7E9D75520}"
call :msiexec "{AFBCA1B9-496C-4AE6-98AE-3EA1CFF65C54}"
call :msiexec "{E82DD0A8-0E5C-4D72-8DDE-41BB0FC06B3E}"
call :msiexec "{15C418EB-7675-42be-B2B3-281952DA014D}"
call :msiexec "{C12953C2-4F15-4A6C-91BC-511B96AE2775}"
call :msiexec "{856A0B42-457D-4BD9-B795-6F942370CA6D}"

:: Sophos Endpoint Defense / SED / Endpoint / Server
"C:\Program Files\Sophos\Endpoint Defense\uninstall.exe"
"C:\Program Files (x86)\Sophos\Endpoint Defense\uninstall.exe"

:: HitmanPro / HMPA managed
"C:\Program Files\HitmanPro.Alert\hmpalert.exe" /uninstall /quiet
"C:\Program Files (x86)\HitmanPro.Alert\hmpalert.exe" /uninstall /quiet

:: HitmanPro
"C:\Program Files\HitmanPro.Alert\uninstall.exe"
"C:\Program Files (x86)\HitmanPro.Alert\uninstall.exe"
"C:\Program Files\HitmanPro\HitmanPro.exe" /uninstall /quiet
"C:\Program Files (x86)\HitmanPro\HitmanPro.exe" /uninstall /quiet

:: Others - Sophos Message Router

:: Others - Sophos Cache Manager / Update Manager
call :msiexec "{2C7A82DB-69BC-4198-AC26-BB862F1BE4D0}"

:: Others - Sophos Certification Manager

:: Others - Sophos Cloud AD Sync Utility
call :msiexec "{94A64BF2-0EFC-47EE-9376-0D14E67A2696}"

:: Others - Sophos Data Recorder

:: Others - Sophos File Integrity Monitoring

:: Others - Sophos Management Host

:: Others - Sophos Management Service

:: Others - Sophos Patch Endpoint Communicator

:: Others - Sophos Patch Endpoint Orchestrator

:: Others - Sophos Patch Server Communicator

:: Others - Sophos Policy Evaluation Service

:: Others - Sophos PureMessage
call :msiexec "{946A74A2-D92E-40CE-B3C5-C6174EC6287D}"

:: Others - Sophos PureMessage Web Agent

:: Others - Sophos PureMessage Running Object Table (ROT)

:: Others - Sophos PureMessage Content Extractor

:: Others - Sophos PureMessage Watchdog Agent

:: Others - Sophos PureMessage Scanner

:: Others - Sophos Encryption For Cloud Storage

:: Others - Sophos Central AD Sync Utility
call :msiexec "{84791325-FCDA-429C-85E1-4167EFB2708F}"

:: Others - Sophos SafeGuard (THIS IS THE ONLY ENTRY FOR THIS APPLICATION IN THIS SCRIPT)
call :msiexec "{957BE63D-2202-4618-BA64-12115A1F8C93}"
call :msiexec "{23140C44-685A-4525-B0E1-FCAA33E89805}"
call :msiexec "{7AA09D93-47ED-470F-BE41-53E0D9D8D87F}"
call :msiexec "{67090957-0E4D-4CE2-93E6-22F98DCE1D26}"
call :msiexec "{E42A36EA-F3F8-49C8-9E0E-0E87CDACAF69}"
call :msiexec "{D102EA66-BFC5-44B6-A371-54FAF5A1B27B}"

:: Others - Sophos SSL VPN Client 2.1 (THIS IS THE ONLY ENTRY FOR THIS APPLICATION IN THIS SCRIPT)
:: "C:\Program Files\Sophos\Sophos SSL VPN Client\Uninstall.exe"
:: "C:\Program Files (x86)\Sophos\Sophos SSL VPN Client\Uninstall.exe"

:: Others - Sophos Virus Removal Tool
call :msiexec "{B829E117-D072-41EA-9606-9826A38D34C1}"

:: Others - Unknown

timeout /t 15 /nobreak
exit /b 0



:Services
call :proxy Services_Disable
call :proxy Services_Stop
call :proxy Services_StopForce
call :proxy Drivers
if "%TryAgain%"=="TRUE" (exit /b 0)
call :proxy Services_Deletion
exit /b 0



:Drivers
call :proxy DriverServices_Disable
call :proxy DriverServices_Stop
call :proxy ProcessesAll_StopForce
call :proxy DriverServices_Uninstall
if "%TryAgain%"=="TRUE" (exit /b 0)
call :proxy DriverServices_Deletion
call :proxy ProcessesAll_StopForce
exit /b 0



:Unregister
call :proxytwo Uninstall_Unreg
call :proxytwo Uninstall_Regsvr
call :proxytwo ProcessesAll_StopForce
exit /b 0



:Deletion
call :proxytwo ScheduledTasks_Deletion
call :proxytwo Registry_Deletion
call :proxytwo Filesystem_Deletion
exit /b 0



:: --------------------------- SUBCHAPTERS ---------------------------
:Services_Disable
:: Graceful attempts of removal are now over. *cracks knuckles* You had your chance, Sophos! The next step is to disable services.

:: Sophos Patch Agent
call :sc_disable "Sophos Patch Agent"

:: Sophos Compliance Agent / NAC / Network Access Compliance
call :sc_disable "Sophos Compliance Agent API"

:: Sophos Network Threat Protection / NTP / Endpoint / Server
call :sc_disable "SntpService"
call :sc_disable "Sophos Network Threat Protection"

:: Sophos System Protection / SSP
call :sc_disable "Sophos System Protection Service"
call :sc_disable "sophossps"

:: Sophos Client Firewall / SCF
call :sc_disable "Sophos Client Firewall Manager"
call :sc_disable "Sophos Client Firewall"

:: Sophos Endpoint Firewall / Endpoint / Server

:: Sophos Anti-Virus / SAV / Endpoint / Server
call :sc_disable "SAVAdminService"
call :sc_disable "Sophos Anti-Virus status reporter"
call :sc_disable "SAVService"
call :sc_disable "Sophos Device Control Service"
call :sc_disable "Sophos Safestore Service"
call :sc_disable "Sophos Safestore"
call :sc_disable "Sophos Web Control Service"
:: Didn't really fall anywhere else - Sophos Web Filter
call :sc_disable "swi_filter"
call :sc_disable "swi_fc"
:: Didn't really fall anywhere else - Sophos Web Intelligence Service
call :sc_disable "swi_service"
call :sc_disable "Sophos Web Intelligence Service"
:: Didn't really fall anywhere else - Sophos Web Intelligence Updater
call :sc_disable "Sophos Web Intelligence Updater"
call :sc_disable "Sophos Web Intelligence Update"
call :sc_disable "swi_update"
call :sc_disable "swi_update_64﻿"
:: Extras
call :sc_disable "Sophos Anti﻿-Virus"

:: Sophos Exploit Prevention / SEP

:: Sophos Remote Management System / RMS

:: Sophos Health / Endpoint / Server
call :sc_disable "Sophos Health Service"

:: Sophos Diagnostic Utility / Endpoint / Server

:: Sophos Management Communications System / MCS / Endpoint / Server
call :sc_disable "Sophos MCS Agent"
call :sc_disable "Sophos MCS Client"

:: Sophos [MCS?] Heartbeat
call :sc_disable "Sophos MCS Heartbeat"

:: Sophos Endpoint Self Help / Endpoint / Server

:: Sophos Lockdown

:: Sophos File Scanner / Endpoint / Server
call :sc_disable "Sophos File Scanner Service"

:: Sophos Standalone Engine / Endpoint / Server

:: Sophos ML Engine

:: Sophos Endpoint / Agent
call :sc_disable "Sophos Agent"

:: Sophos Clean / Endpoint / Server
call :sc_disable "Sophos Clean Service"
call :sc_disable "Sophos Clean"

:: Sophos AutoUpdate XG / Endpoint / Server

:: Sophos AutoUpdate / SAU
call :sc_disable "Sophos AutoUpdate Service"

:: Sophos Endpoint Defense / SED / Endpoint / Server
call :sc_disable "Sophos Endpoint Defense Service"

:: HitmanPro / HMPA managed

:: HitmanPro

:: Others - Sophos Message Router
call :sc_disable "Sophos Message Router"

:: Others - Sophos Cache Manager / Update Manager
call :sc_disable "Sophos Cache Manager"
call :sc_disable "Sophos Update Cache"
call :sc_disable "SUM"

:: Others - Sophos Certification Manager
call :sc_disable "Sophos Certification Manager"

:: Others - Sophos Cloud AD Sync Utility
call :sc_disable "Sophos Cloud AD Sync Utility"

:: Others - Sophos Data Recorder
call :sc_disable "SophosDataRecorderService"

:: Others - Sophos File Integrity Monitoring
call :sc_disable "SophosFIM"

:: Others - Sophos Management Host
call :sc_disable "SophosManagementHostService"

:: Others - Sophos Management Service
call :sc_disable "Sophos Management Service"

:: Others - Sophos Patch Endpoint Communicator
call :sc_disable "SophosPatchEndpointCommunicator"

:: Others - Sophos Patch Endpoint Orchestrator
call :sc_disable "SophosPatchOrchestratorService"

:: Others - Sophos Patch Server Communicator
call :sc_disable "SophosPatchServerCommunicator"

:: Others - Sophos Policy Evaluation Service
call :sc_disable "Sophos Policy Evaluation Service"

:: Others - Sophos PureMessage
call :sc_disable "SavexSrvc"

:: Others - Sophos PureMessage Web Agent
call :sc_disable "SavexWebAgent"

:: Others - Sophos PureMessage Running Object Table (ROT)
call :sc_disable "MMRot"

:: Others - Sophos PureMessage Content Extractor
call :sc_disable "PMContExtrSvc"

:: Others - Sophos PureMessage Watchdog Agent
call :sc_disable "PMEVizsla"

:: Others - Sophos PureMessage Scanner
call :sc_disable "PMScanner"

:: Others - Sophos Encryption For Cloud Storage
call :sc_disable "SGNCloudEncService"

:: Others - Sophos Central AD Sync Utility
call :sc_disable "Sophos Central AD Sync Utility"

:: Others - Unknown
call :sc_disable "sweepupdate"
call :sc_disable "sweepnet"

timeout /t 15 /nobreak
exit /b 0



:Services_Stop
:: The next step is to stop services
:: Sophos Patch Agent
sc stop "Sophos Patch Agent"

:: Sophos Compliance Agent / NAC / Network Access Compliance
sc stop "Sophos Compliance Agent API"

:: Sophos Network Threat Protection / NTP / Endpoint / Server
sc stop "SntpService"
sc stop "Sophos Network Threat Protection"

:: Sophos System Protection / SSP
sc stop "Sophos System Protection Service"
sc stop "sophossps"

:: Sophos Client Firewall / SCF
sc stop "Sophos Client Firewall Manager"
sc stop "Sophos Client Firewall"

:: Sophos Endpoint Firewall / Endpoint / Server

:: Sophos Anti-Virus / SAV / Endpoint / Server
sc stop "SAVAdminService"
sc stop "Sophos Anti-Virus status reporter"
sc stop "SAVService"
sc stop "Sophos Device Control Service"
sc stop "Sophos Safestore Service"
sc stop "Sophos Safestore"
sc stop "Sophos Web Control Service"
:: Didn't really fall anywhere else - Sophos Web Filter
sc stop "swi_filter"
sc stop "swi_fc"
:: Didn't really fall anywhere else - Sophos Web Intelligence Service
sc stop "swi_service"
sc stop "Sophos Web Intelligence Service"
:: Didn't really fall anywhere else - Sophos Web Intelligence Updater
sc stop "Sophos Web Intelligence Updater"
sc stop "Sophos Web Intelligence Update"
sc stop "swi_update"
sc stop "swi_update_64﻿"
:: Extras
sc stop "Sophos Anti﻿-Virus"

:: Sophos Exploit Prevention / SEP

:: Sophos Remote Management System / RMS

:: Sophos Health / Endpoint / Server
sc stop "Sophos Health Service"

:: Sophos Diagnostic Utility / Endpoint / Server

:: Sophos Management Communications System / MCS / Endpoint / Server
sc stop "Sophos MCS Agent"
sc stop "Sophos MCS Client"

:: Sophos [MCS?] Heartbeat
sc stop "Sophos MCS Heartbeat"

:: Sophos Endpoint Self Help / Endpoint / Server

:: Sophos Lockdown

:: Sophos File Scanner / Endpoint / Server
sc stop "Sophos File Scanner Service"

:: Sophos Standalone Engine / Endpoint / Server

:: Sophos ML Engine

:: Sophos Endpoint / Agent
sc stop "Sophos Agent"

:: Sophos Clean / Endpoint / Server
sc stop "Sophos Clean Service"
sc stop "Sophos Clean"

:: Sophos AutoUpdate XG / Endpoint / Server

:: Sophos AutoUpdate / SAU
sc stop "Sophos AutoUpdate Service"

:: Sophos Endpoint Defense / SED / Endpoint / Server
sc stop "Sophos Endpoint Defense Service"

:: HitmanPro / HMPA managed

:: HitmanPro

:: Others - Sophos Message Router
sc stop "Sophos Message Router"

:: Others - Sophos Cache Manager / Update Manager
sc stop "Sophos Cache Manager"
sc stop "Sophos Update Cache"
sc stop "SUM"

:: Others - Sophos Certification Manager
sc stop "Sophos Certification Manager"

:: Others - Sophos Cloud AD Sync Utility
sc stop "Sophos Cloud AD Sync Utility"

:: Others - Sophos Data Recorder
sc stop "SophosDataRecorderService"

:: Others - Sophos File Integrity Monitoring
sc stop "SophosFIM"

:: Others - Sophos Management Host
sc stop "SophosManagementHostService"

:: Others - Sophos Management Service
sc stop "Sophos Management Service"

:: Others - Sophos Patch Endpoint Communicator
sc stop "SophosPatchEndpointCommunicator"

:: Others - Sophos Patch Endpoint Orchestrator
sc stop "SophosPatchOrchestratorService"

:: Others - Sophos Patch Server Communicator
sc stop "SophosPatchServerCommunicator"

:: Others - Sophos Policy Evaluation Service
sc stop "Sophos Policy Evaluation Service"

:: Others - Sophos PureMessage
sc stop "SavexSrvc"

:: Others - Sophos PureMessage Web Agent
sc stop "SavexWebAgent"

:: Others - Sophos PureMessage Running Object Table (ROT)
sc stop "MMRot"

:: Others - Sophos PureMessage Content Extractor
sc stop "PMContExtrSvc"

:: Others - Sophos PureMessage Watchdog Agent
sc stop "PMEVizsla"

:: Others - Sophos PureMessage Scanner
sc stop "PMScanner"

:: Others - Sophos Encryption For Cloud Storage
sc stop "SGNCloudEncService"

:: Others - Sophos Central AD Sync Utility
sc stop "Sophos Central AD Sync Utility"

:: Others - Unknown
sc stop "sweepupdate"
sc stop "sweepnet"

timeout /t 15 /nobreak
exit /b 0



:Services_StopForce
:: The next step is to forcibly terminate running services
:: Others - Unknown (moved to be the first item as a special exception because a lot of these are executables not found anywhere)
taskill /T /F /IM "sweepupdate.exe" /IM "sweepnet.exe" /IM "backgroundscanclient.exe" /IM "sav32cli.exe" /IM "savcleanupservice.exe" /IM "savmain.exe" /IM "savprogress.exe" /IM "savproxy.exe" /IM "sdcdevcon.exe" /IM "wscclient.exe" /IM "clientmrinit.exe" /IM "emlibupdateagentnt.exe" /IM "agentapi.exe" /IM "autoupdateagentnt.exe" /IM "agentasst.exe" /IM "alupdate.exe" /IM "scfmanager.exe"

:: Sophos Patch Agent
taskkill /T /F /IM "spa.exe"

:: Sophos Compliance Agent / NAC / Network Access Compliance

:: Sophos Network Threat Protection / NTP / Endpoint / Server
taskkill /T /F /IM "SntpService.exe"

:: Sophos System Protection / SSP
taskkill /T /F /IM "SSPService.exe" /IM "ssp.exe"

:: Sophos Client Firewall / SCF
taskkill /T /F /IM "SCFManager.exe" /IM "SCFService.exe"

:: Sophos Endpoint Firewall / Endpoint / Server

:: Sophos Anti-Virus / SAV / Endpoint / Server
taskkill /T /F /IM "SAVAdminService.exe" /IM "SavService.exe" /IM "sdcservice.exe" /IM "Safestore.exe" /IM "Safestore64.exe" /IM "swc_service.exe" /IM "swi_filter.exe" /IM "swi_service.exe" /IM "swi_update.exe" /IM "swi_update_64.exe" /IM "swi_fc.exe"

:: Sophos Exploit Prevention / SEP

:: Sophos Remote Management System / RMS

:: Sophos Health / Endpoint / Server
taskkill /T /F /IM "Health.exe"

:: Sophos Diagnostic Utility / Endpoint / Server

:: Sophos Management Communications System / MCS / Endpoint / Server
taskkill /T /F /IM "McsAgent.exe" /IM "McsClient.exe"

:: Sophos [MCS?] Heartbeat
taskkill /T /F /IM "Heartbeat.exe"

:: Sophos Endpoint Self Help / Endpoint / Server

:: Sophos Lockdown

:: Sophos File Scanner / Endpoint / Server
taskkill /T /F /IM "SophosFS.exe"

:: Sophos Standalone Engine / Endpoint / Server

:: Sophos ML Engine

:: Sophos Endpoint / Agent
taskkill /T /F /IM "Sophos UI.exe" /IM "ManagementAgentNT.exe"

:: Sophos Clean / Endpoint / Server
taskkill /T /F /IM "Clean.exe"

:: Sophos AutoUpdate XG / Endpoint / Server

:: Sophos AutoUpdate / SAU
taskkill /T /F /IM "ALsvc.exe" /IM "almon.exe"

:: Sophos Endpoint Defense / SED / Endpoint / Server
taskkill /T /F /IM "SEDService.exe"

:: HitmanPro / HMPA managed

:: HitmanPro

:: Others - Sophos Message Router
taskkill /T /F /IM "RouterNT.exe"

:: Others - Sophos Cache Manager / Update Manager
taskkill /T /F /IM "UpdateCacheService.exe" /IM "SUMService.exe"

:: Others - Sophos Certification Manager
taskkill /T /F /IM "CertificationManagerServiceNT.exe"

:: Others - Sophos Cloud AD Sync Utility
taskkill /T /F /IM "SophosADSyncService.exe"

:: Others - Sophos Data Recorder
taskkill /T /F /IM "SDRService.exe"

:: Others - Sophos File Integrity Monitoring
taskkill /T /F /IM "SophosFIMService.exe"

:: Others - Sophos Management Host
taskkill /T /F /IM "Sophos.FrontEnd.Service.exe"

:: Others - Sophos Management Service
taskkill /T /F /IM "MgntSvc.exe"

:: Others - Sophos Patch Endpoint Communicator
taskkill /T /F /IM "PatchEndpointCommunicator.exe"

:: Others - Sophos Patch Endpoint Orchestrator
taskkill /T /F /IM "PatchEndpointOrchestrator.exe"

:: Others - Sophos Patch Server Communicator
taskkill /T /F /IM "PatchServerCommunicator.exe"

:: Others - Sophos Policy Evaluation Service
taskkill /T /F /IM "Sophos.PolicyEvaluation.Service.exe"

:: Others - Sophos PureMessage
taskkill /T /F /IM "SavexSrvc.exe"

:: Others - Sophos PureMessage Web Agent
taskkill /T /F /IM "SavexWebAgent.exe"

:: Others - Sophos PureMessage Running Object Table (ROT)
taskkill /T /F /IM "MMRot.exe"

:: Others - Sophos PureMessage Content Extractor
taskkill /T /F /IM "PMContExtrSvc.exe"

:: Others - Sophos PureMessage Watchdog Agent
taskkill /T /F /IM "PMEVizsla.exe"

:: Others - Sophos PureMessage Scanner
taskkill /T /F /IM "PMScanner.exe"

:: Others - Sophos Encryption For Cloud Storage
taskkill /T /F /IM "SGN_MasterServicen.exe"

:: Others - Sophos Central AD Sync Utility
taskkill /T /F /IM "SophosADSyncService.exe"
exit /b 0



:Services_Deletion
:: The next step is to delete all Sophos services
:: Sophos Patch Agent
call :sc_delete "Sophos Patch Agent"

:: Sophos Compliance Agent / NAC / Network Access Compliance
call :sc_delete "Sophos Compliance Agent API"

:: Sophos Network Threat Protection / NTP / Endpoint / Server
call :sc_delete "SntpService"
call :sc_delete "Sophos Network Threat Protection"

:: Sophos System Protection / SSP
call :sc_delete "Sophos System Protection Service"
call :sc_delete "sophossps"

:: Sophos Client Firewall / SCF
call :sc_delete "Sophos Client Firewall Manager"
call :sc_delete "Sophos Client Firewall"

:: Sophos Endpoint Firewall / Endpoint / Server

:: Sophos Anti-Virus / SAV / Endpoint / Server
call :sc_delete "SAVAdminService"
call :sc_delete "Sophos Anti-Virus status reporter"
call :sc_delete "SAVService"
call :sc_delete "Sophos Device Control Service"
call :sc_delete "Sophos Safestore Service"
call :sc_delete "Sophos Safestore"
call :sc_delete "Sophos Web Control Service"
:: Didn't really fall anywhere else - Sophos Web Filter
call :sc_delete "swi_filter"
call :sc_delete "swi_fc"
:: Didn't really fall anywhere else - Sophos Web Intelligence Service
call :sc_delete "swi_service"
call :sc_delete "Sophos Web Intelligence Service"
:: Didn't really fall anywhere else - Sophos Web Intelligence Updater
call :sc_delete "Sophos Web Intelligence Updater"
call :sc_delete "Sophos Web Intelligence Update"
call :sc_delete "swi_update"
sc delete "swi_update_64"
call :sc_delete "swi_update_64﻿"
:: Extras
call :sc_delete "Sophos Anti﻿-Virus"

:: Sophos Exploit Prevention / SEP

:: Sophos Remote Management System / RMS

:: Sophos Health / Endpoint / Server
call :sc_delete "Sophos Health Service"

:: Sophos Diagnostic Utility / Endpoint / Server

:: Sophos Management Communications System / MCS / Endpoint / Server
call :sc_delete "Sophos MCS Agent"
call :sc_delete "Sophos MCS Client"

:: Sophos [MCS?] Heartbeat
call :sc_delete "Sophos MCS Heartbeat"

:: Sophos Endpoint Self Help / Endpoint / Server

:: Sophos Lockdown

:: Sophos File Scanner / Endpoint / Server
call :sc_delete "Sophos File Scanner Service"

:: Sophos Standalone Engine / Endpoint / Server

:: Sophos ML Engine

:: Sophos Endpoint / Agent
call :sc_delete "Sophos Agent"

:: Sophos Clean / Endpoint / Server
call :sc_delete "Sophos Clean Service"
call :sc_delete "Sophos Clean"

:: Sophos AutoUpdate XG / Endpoint / Server

:: Sophos AutoUpdate / SAU
call :sc_delete "Sophos AutoUpdate Service"

:: Sophos Endpoint Defense / SED / Endpoint / Server
call :sc_delete "Sophos Endpoint Defense Service"

:: HitmanPro / HMPA managed

:: HitmanPro

:: Others - Sophos Message Router
call :sc_delete "Sophos Message Router"

:: Others - Sophos Cache Manager / Update Manager
call :sc_delete "Sophos Cache Manager"
call :sc_delete "Sophos Update Cache"
call :sc_delete "SUM"

:: Others - Sophos Certification Manager
call :sc_delete "Sophos Certification Manager"

:: Others - Sophos Cloud AD Sync Utility
call :sc_delete "Sophos Cloud AD Sync Utility"

:: Others - Sophos Data Recorder
call :sc_delete "SophosDataRecorderService"

:: Others - Sophos File Integrity Monitoring
call :sc_delete "SophosFIM"

:: Others - Sophos Management Host
call :sc_delete "SophosManagementHostService"

:: Others - Sophos Management Service
call :sc_delete "Sophos Management Service"

:: Others - Sophos Patch Endpoint Communicator
call :sc_delete "SophosPatchEndpointCommunicator"

:: Others - Sophos Patch Endpoint Orchestrator
call :sc_delete "SophosPatchOrchestratorService"

:: Others - Sophos Patch Server Communicator
call :sc_delete "SophosPatchServerCommunicator"

:: Others - Sophos Policy Evaluation Service
call :sc_delete "Sophos Policy Evaluation Service"

:: Others - Sophos PureMessage
call :sc_delete "SavexSrvc"

:: Others - Sophos PureMessage Web Agent
call :sc_delete "SavexWebAgent"

:: Others - Sophos PureMessage Running Object Table (ROT)
call :sc_delete "MMRot"

:: Others - Sophos PureMessage Content Extractor
call :sc_delete "PMContExtrSvc"

:: Others - Sophos PureMessage Watchdog Agent
call :sc_delete "PMEVizsla"

:: Others - Sophos PureMessage Scanner
call :sc_delete "PMScanner"

:: Others - Sophos Encryption For Cloud Storage
call :sc_delete "SGNCloudEncService"

:: Others - Sophos Central AD Sync Utility
call :sc_delete "Sophos Central AD Sync Utility"

:: Others - Unknown
call :sc_delete "sweepupdate"
call :sc_delete "sweepnet"
exit /b 0



:DriverServices_Disable
:: The next step is to disable driver services
:: Sophos Network Threat Protection Driver (Sophos Network Threat Protection / NTP / Endpooint / Server)
call :sc_disable "sntp"

:: SAV on-access mini-filter driver (Sophos Anti-Virus)
call :sc_disable "SAVOnAccess"

:: Sophos Web Intelligence callout driver (Sophos Anti-Virus)
call :sc_disable "swi_callout"

:: Sophos Early Launch AntiMalware Driver (Sophos Anti-Virus?)
call :sc_disable "Sophos ELAM"

:: Sophos Boot Driver (Sophos Anti-Virus)
call :sc_disable "SophosBootDriver"

:: Sophos CD-Rom Class filter driver (Sophos Device Control?)
call :sc_disable "sdcfilter"

:: Sophos Endpoint Defense
call :sc_disable "Sophos Endpoint Defense"
exit /b 0



:DriverServices_Stop
:: The next step is to stop driver services
:: Sophos Network Threat Protection Driver (Sophos Network Threat Protection / NTP / Endpooint / Server)
call :scd_stop "sntp"

:: SAV on-access mini-filter driver (Sophos Anti-Virus)
call :scd_stop "SAVOnAccess"

:: Sophos Web Intelligence callout driver (Sophos Anti-Virus)
call :scd_stop "swi_callout"

:: Sophos Early Launch AntiMalware Driver (Sophos Anti-Virus?)
call :scd_stop "Sophos ELAM"

:: Sophos Boot Driver (Sophos Anti-Virus)
call :scd_stop "SophosBootDriver"

:: Sophos CD-Rom Class filter driver (Sophos Device Control?)
call :scd_stop "sdcfilter"

:: Sophos Endpoint Defense
call :scd_stop "Sophos Endpoint Defense"

timeout /t 15 /nobreak
exit /b 0



:DriverServices_Uninstall
:: The next step is to uninstall all Sophos driver services via INF files
:: Sophos Network Threat Protection Driver (Sophos Network Threat Protection / NTP / Endpooint / Server)
wmic sysdriver where name="sntp" call delete

:: SAV on-access mini-filter driver (Sophos Anti-Virus)
wmic sysdriver where name="SAVOnAccess" call delete

:: Sophos Web Intelligence callout driver (Sophos Anti-Virus)
wmic sysdriver where name="swi_callout" call delete

:: Sophos Early Launch AntiMalware Driver (Sophos Anti-Virus?)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosEL.inf")

if exist "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf" (rundll32 advpack.dll,LaunchINFSection "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf",UnInstall)
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\Program Files\Sophos\Endpoint Defense\SophosEL.inf")

wmic sysdriver where name="SophosEL" call delete
wmic sysdriver where name="Sophos ELAM" call delete

:: Sophos Boot Driver (Sophos Anti-Virus)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_amd64\SophosBootDriver.inf")

if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\win7_i386\SophosBootDriver.inf")

if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wxp_i386\SophosBootDriver.inf")

if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\savxp\drivers\boottasks\wnet_amd64\SophosBootDriver.inf")

wmic sysdriver where name="SophosBootDriver" call delete

:: Sophos CD-Rom Class filter driver (Sophos Device Control?)
wmic sysdriver where name="sdcfilter" call delete

:: Sophos Endpoint Defense
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")

if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win8Uninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win8Uninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")

if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win7Uninstall 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win7Uninstall.Services 132 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (rundll32 advpack.dll,LaunchINFSection "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf",UnInstall)
if exist "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\ProgramData\Sophos\AutoUpdate\Cache\decoded\sed64\SophosED.inf")

if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection DefaultUninstall.Services 132 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (rundll32 advpack.dll,LaunchINFSection "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf",UnInstall)
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")

if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win8Uninstall 132 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win8Uninstall.Services 132 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (rundll32 advpack.dll,LaunchINFSection "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf",UnInstall)
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")

if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win7Uninstall 132 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (RUNDLL32 SETUPAPI.DLL,InstallHinfSection Win7Uninstall.Services 132 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (rundll32 advpack.dll,LaunchINFSection "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf",UnInstall)
if exist "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf" (rundll32 syssetup.dll,SetupInfObjectInstallAction Uninstall.NT 4 "C:\Program Files\Sophos\Endpoint Defense\SophosED.inf")

wmic sysdriver where name="SophosED" call delete
wmic sysdriver where name="Sophos Endpoint Defense" call delete
exit /b 0



:DriverServices_Deletion
:: The next step is to delete all Sophos driver services
:: We will add a handful of driver files to the PendingFileRenameOperations registry value using a script from https://gallery.technet.microsoft.com/scriptcenter/Register-FileToDelete-0cbb00bb developed by Boe Prox. This script must exist in the same directory as this batch script.
:: These couple magic one-liners will basically create the script for us if it does not exist, further allowing this batch script as being the only file to handle
if not exist "%~dp0Register-FileToDelete.ps1" (call :PoShScript&if not exist "%~dp0Register-FileToDelete.ps1" (echo Failed to create Register-FileToDelete.ps1 script) else (echo Successfully created Register-FileToDelete.ps1 script&echo Executing Register-FileToDelete.ps1 script)) else (echo Executing Register-FileToDelete.ps1 script)
if exist "%~dp0Register-FileToDelete.ps1" ((powershell -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '%~dp0Register-FileToDelete.ps1';Register-FileToDelete -Source 'C:\Windows\System32\drivers\SophosEL.sys';Register-FileToDelete -Source 'C:\Windows\System32\drivers\SophosED.sys';Register-FileToDelete -Source 'C:\Windows\System32\drivers\SophosED.man';Register-FileToDelete -Source 'C:\Windows\System32\drivers\SophosBootDriver.sys';Register-FileToDelete -Source 'C:\Windows\System32\SophosNA.exe';Register-FileToDelete -Source 'C:\Windows\System32\SophosBootTasks.exe'") 2> nul&echo Register-FileToDelete.ps1 script executed&(del /Q /S "%~dp0Register-FileToDelete.ps1")>nul 2>&1&call :DriverServices_Deletion_Sub) else (echo Failed to execute Register-FileToDelete.ps1 script&(del /Q /S "%~dp0Register-FileToDelete.ps1")>nul 2>&1)
exit /b 0



:DriverServices_Deletion_Sub
:: This label will only be executed if we can successfully mark files for deletion-on-reboot
:: We won't use the 'reg delete' because 'sc delete' will schedule the service for deletion on reboot of the Operating System. We don't want to delete these services if the drivers are actively operating live.

:: SAV on-access mini-filter driver
sc delete "SAVOnAccess"
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SAVOnAccess" /f

:: Sophos CD-Rom Class filter driver
sc delete "sdcfilter"
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\sdcfilter" /f

:: Sophos Network Threat Protection Driver
sc delete "sntp"
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\sntp" /f

:: Sophos Early Launch AntiMalware Driver
sc delete "Sophos ELAM"
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sophos ELAM" /f

:: Sophos 
sc delete "Sophos Endpoint Defense"
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense" /f

:: Sophos Web Intelligence callout driver
sc delete "swi_callout"
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\swi_callout" /f

:: Sophos Boot Driver
sc delete "SophosBootDriver"
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SophosBootDriver" /f

:: Setting PendingReboot flag
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" /f
exit /b 0



:Uninstall_Unreg
:: The next step is to unregister EXEs to known Sophos files (/UnRegServer and -Uninstall methods)
:: https://www.itninja.com/software/sophos/anti-virus/7-201
:: https://www.experts-exchange.com/questions/23058062/Sophos-Anti-Virus-Uninstall-Script.html
:: https://community.sophos.com/kb/en-us/127805

:: Sophos Patch Agent

:: Sophos Compliance Agent / NAC / Network Access Compliance

:: Sophos Network Threat Protection / NTP / Endpoint / Server

:: Sophos System Protection / SSP

:: Sophos Client Firewall / SCF
if exist "C:\Program Files\Sophos\Sophos Client Firewall\SCFManager.exe" "C:\Program Files\Sophos\Sophos Client Firewall\SCFManager.exe" /UnregServer
if exist "C:\Program Files (x86)\Sophos\Sophos Client Firewall\SCFManager.exe" "C:\Program Files (x86)\Sophos\Sophos Client Firewall\SCFManager.exe" /UnregServer
if exist "C:\Program Files\Sophos\Sophos Client Firewall\SCFService.exe" "C:\Program Files\Sophos\Sophos Client Firewall\SCFService.exe" /UnregServer
if exist "C:\Program Files (x86)\Sophos\Sophos Client Firewall\SCFService.exe" "C:\Program Files (x86)\Sophos\Sophos Client Firewall\SCFService.exe" /UnregServer

:: Sophos Endpoint Firewall / Endpoint / Server

:: Sophos Anti-Virus / SAV / Endpoint / Server
if exist "C:\Program Files\Sophos\Sophos Anti-Virus\SavService.exe" "C:\Program Files\Sophos\Sophos Anti-Virus\SavService.exe" /unregserver
if exist "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\SavService.exe" "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\SavService.exe" /unregserver
if exist "C:\Program Files\Sophos\Sophos Anti-Virus\SavAdminService.exe" "C:\Program Files\Sophos\Sophos Anti-Virus\SavAdminService.exe" /unregserver
if exist "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\SavAdminService.exe" "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\SavAdminService.exe" /unregserver
if exist "C:\Program Files\Sophos\Sophos Anti-Virus\sdcservice.exe" "C:\Program Files\Sophos\Sophos Anti-Virus\sdcservice.exe" /unregserver
if exist "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sdcservice.exe" "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sdcservice.exe" /unregserver
if exist "C:\Program Files\Sophos\Sophos Anti-Virus\Web Control\swc_service.exe" "C:\Program Files\Sophos\Sophos Anti-Virus\Web Control\swc_service.exe" /unregserver
if exist "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\Web Control\swc_service.exe" "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\Web Control\swc_service.exe" /unregserver

:: Sophos Exploit Prevention / SEP

:: Sophos Remote Management System / RMS
if exist "C:\Program Files\Sophos\Remote Management System\ManagementAgentNT.exe" "C:\Program Files\Sophos\Remote Management System\ManagementAgentNT.exe" -uninstall
if exist "C:\Program Files (x86)\Sophos\Remote Management System\ManagementAgentNT.exe" "C:\Program Files (x86)\Sophos\Remote Management System\ManagementAgentNT.exe" -uninstall
if exist "C:\Program Files\Sophos\Remote Management System\AutoUpdateAgentNT.exe" "C:\Program Files\Sophos\Remote Management System\AutoUpdateAgentNT.exe" -uninstall
if exist "C:\Program Files (x86)\Sophos\Remote Management System\AutoUpdateAgentNT.exe" "C:\Program Files (x86)\Sophos\Remote Management System\AutoUpdateAgentNT.exe" -uninstall
if exist "C:\Program Files\Sophos\Remote Management System\RouterNT.exe" "C:\Program Files\Sophos\Remote Management System\RouterNT.exe" -uninstall
if exist "C:\Program Files (x86)\Sophos\Remote Management System\RouterNT.exe" "C:\Program Files (x86)\Sophos\Remote Management System\RouterNT.exe" -uninstall

:: Sophos Health / Endpoint / Server

:: Sophos Diagnostic Utility / Endpoint / Server

:: Sophos Management Communications System / MCS / Endpoint / Server

:: Sophos [MCS?] Heartbeat

:: Sophos Endpoint Self Help / Endpoint / Server

:: Sophos Lockdown

:: Sophos File Scanner / Endpoint / Server

:: Sophos Standalone Engine / Endpoint / Server

:: Sophos ML Engine

:: Sophos Endpoint / Agent

:: Sophos Clean / Endpoint / Server

:: Sophos AutoUpdate XG / Endpoint / Server

:: Sophos AutoUpdate / SAU
if exist "C:\Program Files\Sophos\AutoUpdate\ALSvc.exe" "C:\Program Files\Sophos\AutoUpdate\ALSvc.exe" /unregserver
if exist "C:\Program Files (x86)\Sophos\AutoUpdate\ALSvc.exe" "C:\Program Files (x86)\Sophos\AutoUpdate\ALSvc.exe" /unregserver
if exist "C:\Program Files\Sophos\AutoUpdate\ALMon.exe" "C:\Program Files\Sophos\AutoUpdate\ALMon.exe" /unregserver
if exist "C:\Program Files (x86)\Sophos\AutoUpdate\ALMon.exe" "C:\Program Files (x86)\Sophos\AutoUpdate\ALMon.exe" /unregserver

:: Sophos Endpoint Defense / SED / Endpoint / Server

:: HitmanPro / HMPA managed

:: HitmanPro

:: Others - Sophos Message Router

:: Others - Sophos Cache Manager / Update Manager

:: Others - Sophos Certification Manager

:: Others - Sophos Cloud AD Sync Utility

:: Others - Sophos Data Recorder

:: Others - Sophos File Integrity Monitoring

:: Others - Sophos Management Host

:: Others - Sophos Management Service

:: Others - Sophos Patch Endpoint Communicator

:: Others - Sophos Patch Endpoint Orchestrator

:: Others - Sophos Patch Server Communicator

:: Others - Sophos Policy Evaluation Service

:: Others - Sophos PureMessage

:: Others - Sophos PureMessage Web Agent

:: Others - Sophos PureMessage Running Object Table (ROT)

:: Others - Sophos PureMessage Content Extractor

:: Others - Sophos PureMessage Watchdog Agent

:: Others - Sophos PureMessage Scanner

:: Others - Sophos Encryption For Cloud Storage

:: Others - Sophos Central AD Sync Utility

:: Others - Unknown

exit /b 0



:Uninstall_Regsvr
:: The next step is to unregister DLLs to known Sophos files (REGSVR32 method)
:: https://www.labtechgeek.com/topic/4274-sophos-removal-script/
:: https://rmccurdy.com/scripts/SOSO.txt
:: https://www.experts-exchange.com/questions/23058062/Sophos-Anti-Virus-Uninstall-Script.html

:: Nuke everything
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files\Sophos\*.dll"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files\Common Files\Sophos\*.dll"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files (x86)\Sophos\*.dll"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files (x86)\Common Files\Sophos\*.dll"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\ProgramData\Sophos\*.dll"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files\Sophos\*.exe"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files\Common Files\Sophos\*.exe"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files (x86)\Sophos\*.exe"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\Program Files (x86)\Common Files\Sophos\*.exe"') do @(regsvr32 /U /S "%%~a")
for /f "tokens=*" %%a in ('dir /S /B "C:\ProgramData\Sophos\*.exe"') do @(regsvr32 /U /S "%%~a")
exit /b 0



:ScheduledTasks_Deletion
schtasks /delete /F /TN "AdwarePUAScan"
schtasks /delete /F /TN "RootkitScan"
schtasks /delete /F /TN "Sophos_InstTask"
exit /b 0



:Registry_Deletion
:: The next step is to delete all Sophos registry keys and values

:: BootExecute
(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute" | find "Sophos")>nul && (reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t "REG_MULTI_SZ" /d "autocheck autochk *" /f)

:: Autoruns
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Sophos UI.exe" /f

:: Context menus
reg delete "HKLM\SOFTWARE\Classes\SavSecurity.SecurityManager" /f
reg delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\SavShellExt" /f
reg delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\SavShellExt" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\SavShellExt" /f
reg delete "HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\SavShellExt" /f

:: Check if any Sophos providers are registered with WinSock
(netsh winsock show catalog | find /I "Sophos")>nul && (call :proxy WinSock) || (echo.)

:: We are flagging some miscellaneous files for deletion on boot due to their extra stubbornness for clinging on to the system
if not exist "%~dp0Register-FileToDelete.ps1" (call :PoShScript&if not exist "%~dp0Register-FileToDelete.ps1" (echo Failed to create Register-FileToDelete.ps1 script) else (echo Successfully created Register-FileToDelete.ps1 script&echo Executing Register-FileToDelete.ps1 script)) else (echo Executing Register-FileToDelete.ps1 script)
if exist "%~dp0Register-FileToDelete.ps1" ((powershell -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '%~dp0Register-FileToDelete.ps1';Register-FileToDelete -Source 'C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sophos_detoured.dll';Register-FileToDelete -Source 'C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sophos_detoured_x64.dll';Register-FileToDelete -Source 'C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sophos_detoured.dll';Register-FileToDelete -Source 'C:\Program Files\Sophos\Sophos Anti-Virus\sophos_detoured_x64.dll';Register-FileToDelete -Source 'C:\Program Files\Sophos\Sophos Anti-Virus\sophos_detoured.dll';Register-FileToDelete -Source 'C:\ProgramData\Sophos\Web Intelligence\swi_ifslsp.dll';Register-FileToDelete -Source 'C:\ProgramData\Sophos\Web Intelligence\swi_ifslsp_64.dll';Register-FileToDelete -Source 'C:\SophosBootTasks.txt';Register-FileToDelete -Source 'C:\ProgramData\Sophos\AutoUpdate\Cache\sophos_autoupdate1.dir\SophosUpdate.exe';Register-FileToDelete -Source 'C:\ProgramData\Sophos';Register-FileToDelete -Source 'C:\Program Files\Sophos';Register-FileToDelete -Source 'C:\Program Files (x86)\Sophos';Register-FileToDelete -Source 'C:\Program Files\Common Files\Sophos';Register-FileToDelete -Source 'C:\Program Files (x86)\Common Files\Sophos';Register-FileToDelete -Source 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos';Get-ChildItem -Recurse 'C:\Program Files (x86)\Common Files\Sophos' | ForEach-Object {Register-FileToDelete -Source $_.FullName};Get-ChildItem -Recurse 'C:\Program Files (x86)\Sophos' | ForEach-Object {Register-FileToDelete -Source $_.FullName};Get-ChildItem -Recurse 'C:\Program Files\Common Files\Sophos' | ForEach-Object {Register-FileToDelete -Source $_.FullName};Get-ChildItem -Recurse 'C:\Program Files\Sophos' | ForEach-Object {Register-FileToDelete -Source $_.FullName};") 2> nul&echo Register-FileToDelete.ps1 script executed&(del /Q /S "%~dp0Register-FileToDelete.ps1")>nul 2>&1) else (echo Failed to execute Register-FileToDelete.ps1 script&(del /Q /S "%~dp0Register-FileToDelete.ps1")>nul 2>&1)

:: Others
reg delete "HKCU\SOFTWARE\Sophos" /f
reg delete "HKCU\SOFTWARE\Wow6432Node\Sophos" /f
reg delete "HKLM\SOFTWARE\Sophos" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Sophos" /f
for /f "tokens=*" %%a in ('reg query HKU') do @(reg delete "HKU\%%~a\SOFTWARE\Sophos" /f)
for /f "tokens=*" %%a in ('reg query HKU') do @(reg delete "HKU\%%~a\SOFTWARE\Wow6432Node\Sophos" /f)
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" ^| find "Sophos"') do @(reg delete "%%~a" /f)
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ^| find "Sophos"') do @(reg delete "%%~a" /f)
for /f "tokens=1 delims=*" %%a in ('net localgroup ^| find "Sophos"') do @(net localgroup "%%~a" /DELETE)2> nul

:: As undesirable it may be to touch the AppInit_DLLs registry value, we have to because it presents a security risk to the system by leaving Sophos in the registry data of this registry value. We will make a registry key backup and save it to "C:\Windows\Temp\AppInitDLLs_*.reg" before making modifications.
:: Microsoft does not recommend that vendors use this registry value (https://support.microsoft.com/en-us/help/197571/working-with-the-appinit-dlls-registry-value)
(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs | find /I "Sophos")>nul&&(call :AppInit_DLLs_x86)||((reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs | find /I "Sophos")>nul&&(call :AppInit_DLLs_x64)||(echo AppInit_DLLs is clean))

wmic /failfast:on product where "name like '%%Sophos%%'" call uninstall /nointeractive && shutdown /a
wmic product where "name like '%%Sophos%%'" call uninstall

for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%%~a" /f)
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%%~a" /f)

for /f "tokens=6 delims=\" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\MATS\WindowsInstaller" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(msiexec /X "%%~a" /qn /norestart REBOOT=REALLYSUPPRESS)
for /f "tokens=7 delims=\" %%a in ('reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\MATS\WindowsInstaller" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(msiexec /X "%%~a" /qn /norestart REBOOT=REALLYSUPPRESS)

:: Largely untested
::for /f "tokens=6 delims=\" %a in ('reg query "HKLM\SOFTWARE\Microsoft\MATS\WindowsInstaller" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Microsoft\MATS\WindowsInstaller\%~a" /f)
::for /f "tokens=7 delims=\" %a in ('reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\MATS\WindowsInstaller" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\MATS\WindowsInstaller\%~a" /f)

:: Largely untested
::for /f "tokens=*" %a in ('reg query "HKLM\SOFTWARE\Classes" ^| find "Sophos"') do @(reg delete "%~a" /f)
::for /f "tokens=*" %a in ('reg query "HKLM\SOFTWARE\Classes\AppID" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%~a" /f)
::for /f "tokens=*" %a in ('reg query "HKLM\SOFTWARE\Classes\Wow6432Node\AppID" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%~a" /f)
::for /f "tokens=5 delims=\" %a in ('reg query "HKLM\SOFTWARE\Classes\CLSID" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Classes\CLSID\%~a" /f)
::for /f "tokens=6 delims=\" %a in ('reg query "HKLM\SOFTWARE\Classes\Wow6432Node\CLSID" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\%~a" /f)
::for /f "tokens=5 delims=\" %a in ('reg query "HKLM\SOFTWARE\Classes\Interface" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Classes\Interface\%~a" /f)
::for /f "tokens=6 delims=\" %a in ('reg query "HKLM\SOFTWARE\Classes\Wow6432Node\Interface" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Classes\Wow6432Node\Interface\%~a" /f)
::for /f "tokens=5 delims=\" %a in ('reg query "HKLM\SOFTWARE\Classes\TypeLib" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Classes\TypeLib\%~a" /f)
::for /f "tokens=6 delims=\" %a in ('reg query "HKLM\SOFTWARE\Classes\Wow6432Node\TypeLib" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "HKLM\SOFTWARE\Classes\Wow6432Node\TypeLib\%~a" /f)
::for /f "tokens=*" %a in ('reg query "HKLM\SOFTWARE\LabTech\Service\DeviceLibrary" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%~a" /f)
::for /f "tokens=*" %a in ('reg query "HKLM\SOFTWARE\LabTech\Service\VirusScanners" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%~a" /f)
::for /f "tokens=*" %a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components" /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%~a" /f)

:: I haven't figured out a good way to just delete registry values that are stored with a name that is a full path
:: Registry values exist at "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs: Name <full path to DLL/EXE> + Type REG_DWORD + Data 1
:: Registry values exist at "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders: Name <full path ending with \> + Type REG_SZ + Data 1 (sometimes)

:: Largely untested
::reg delete "HKLM\SOFTWARE\Microsoft\Security Center\Monitoring\SophosAntivirus" /f
::reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Security Center\Monitoring\SophosAntivirus" /f

exit /b 0



:WinSock
:: Backup WinSock entries for Sophos
(for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(echo.)) && (for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(for /f "tokens=*" %%c in ('reg query "HKLM\SYSTEM\CurrentControlSet\services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64" /d /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(for /f "tokens=9 delims=\" %%d in ('echo %%~c') do @(reg export "%%~c" "C:\Windows\Temp\Winsock64_%%~d_%%~b.reg")))) || (for /f "tokens=*" %%c in ('reg query "HKLM\SYSTEM\CurrentControlSet\services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64" /d /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(for /f "tokens=9 delims=\" %%d in ('echo %%~c') do @(echo reg export "%%~c" "C:\Windows\Temp\Winsock64_%%~d_00000000000000.reg")))&(for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(echo.)) && (for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(for /f "tokens=*" %%c in ('reg query "HKLM\SYSTEM\CurrentControlSet\services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries" /d /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(for /f "tokens=9 delims=\" %%d in ('echo %%~c') do @(reg export "%%~c" "C:\Windows\Temp\Winsock32_%%~d_%%~b.reg")))) || (for /f "tokens=*" %%c in ('reg query "HKLM\SYSTEM\CurrentControlSet\services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries" /d /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(for /f "tokens=9 delims=\" %%d in ('echo %%~c') do @(echo reg export "%%~c" "C:\Windows\Temp\Winsock32_%%~d_00000000000000.reg")))

:: Deletion of WinSock entries for Sophos via registry
:: Commented out because I believe "netsh winsock remove provider #" is the proper and graceful way of removing the providers and I have not been successful in putting together PoSh magic to parse the output of "netsh winsock show catalog" to select the Catalog Entry ID for Descriptions containing Sophos ... to feed into the "netsh winsock remove provider #" command
:: See https://stackoverflow.com/questions/54083702/parsing-the-output-of-a-legacy-console-application-with-powershell-to-select-val
::(for /f "tokens=*" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\services\WinSock2\Parameters\Protocol_Catalog9" /d /s /f "Sophos" ^| find "HKEY_LOCAL_MACHINE"') do @(reg delete "%%~b" /f))

:: Reset WinSock /should/ clear out providers
:: Uncommented for public-developmental release
netsh winsock reset
exit /b 0



:AppInit_DLLs_x64
:: Backup the parent registry key where AppInit_DLLs exists
(for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(echo.)) && (for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" "C:\Windows\Temp\AppInitDLLs_%%~b.reg")) || (reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" "C:\Windows\Temp\AppInitDLLs_00000000000000.reg")
:: Clear the registry data for registry value AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /t REG_SZ /f
exit /b 0



:AppInit_DLLs_x86
:: Backup the parent registry key where AppInit_DLLs exists
(for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(echo.)) && (for /f "tokens=1 delims=. skip=1" %%b in ('wmic os get localdatetime ^| findstr "."') do @(reg export "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" "C:\Windows\Temp\AppInitDLLs_%%~b.reg")) || (reg export "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" "C:\Windows\Temp\AppInitDLLs_00000000000000.reg")
:: Clear the registry data for registry value AppInit_DLLs
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /t REG_SZ /f
exit /b 0



:Filesystem_Deletion
:: The next step is to nuke all Sophos folders and files from orbit

rd /Q /S "C:\Program Files (x86)\Common Files\Sophos" || ((for /f %%a in ('dir /B /S "C:\Program Files (x86)\Common Files\Sophos"') do @(takeown /f "%%~a" /r /d y&del /Q /S "%%~a"&rd /Q /S "%%~a"))&rd /Q /S "C:\Program Files (x86)\Common Files\Sophos")
rd /Q /S "C:\Program Files (x86)\Sophos" || ((for /f %%a in ('dir /B /S "C:\Program Files (x86)\Sophos"') do @(takeown /f "%%~a" /r /d y&del /Q /S "%%~a"&rd /Q /S "%%~a"))&rd /Q /S "C:\Program Files (x86)\Sophos")
rd /Q /S "C:\Program Files\Common Files\Sophos" || ((for /f %%a in ('dir /B /S "C:\Program Files\Common Files\Sophos"') do @(takeown /f "%%~a" /r /d y&del /Q /S "%%~a"&rd /Q /S "%%~a"))&rd /Q /S "C:\Program Files\Common Files\Sophos")
rd /Q /S "C:\Program Files\Sophos" || ((for /f %%a in ('dir /B /S "C:\Program Files\Sophos"') do @(takeown /f "%%~a" /r /d y&del /Q /S "%%~a"&rd /Q /S "%%~a"))&rd /Q /S "C:\Program Files\Sophos")
rd /Q /S "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos" || ((for /f %%a in ('dir /B /S "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos"') do @(takeown /f "%%~a" /r /d y&del /Q /S "%%~a"&rd /Q /S "%%~a"))&rd /Q /S "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos")
rd /Q /S "C:\ProgramData\Sophos" || ((for /f %%a in ('dir /B /S "C:\ProgramData\Sophos"') do @(takeown /f "%%~a" /r /d y&del /Q /S "%%~a"&rd /Q /S "%%~a"))&rd /Q /S "C:\ProgramData\Sophos")
exit /b 0



:: --------------------------- SUBROUTINES ---------------------------

:: The proxy and proxytwo labels are here to help with inserting 'pause' for controlled debugging and analysis of command outputs
:proxy
call :%1
::pause
exit /b 0

:proxytwo
call :%1
::pause
exit /b 0

:msiexec
:: Subroutine for silent MSI uninstallation
msiexec /X %1 /qn /norestart REBOOT=REALLYSUPPRESS
exit /b 0

:sc_disable
:: Subroutine for disabling a service
(sc config %1 start= disabled)2> nul
exit /b 0

:sc_delete
:: Subroutine for deleting a service
(sc delete %1)2> nul

:: Stripping surrounding quotes
set scvar=%1

:: The [commented] command below will print the value of the variable
::set scvar

:: The command below will strip the surrounding quotes
set scvar=%scvar:"=%

::set scvar

:: Deleting services via registry to be extra sure
(reg delete "HKLM\SYSTEM\CurrentControlSet\Services\%scvar%" /f&reg delete "HKLM\SYSTEM\ControlSet000\Services\%scvar%" /f&reg delete "HKLM\SYSTEM\ControlSet001\Services\%scvar%" /f&reg delete "HKLM\SYSTEM\ControlSet002\Services\%scvar%" /f&reg delete "HKLM\SYSTEM\ControlSet003\Services\%scvar%" /f)2> nul

:: The command below will clear the value of the variable
set scvar=
exit /b 0

:scd_stop
:: Subroutine for attempting to stop File System Driver filters
fltmc detach %1 A:
fltmc detach %1 B:
fltmc detach %1 C:
fltmc detach %1 D:
fltmc detach %1 E:
fltmc detach %1 F:
fltmc detach %1 G:
fltmc detach %1 H:
fltmc detach %1 I:
fltmc detach %1 J:
fltmc detach %1 K:
fltmc detach %1 L:
fltmc detach %1 M:
fltmc detach %1 N:
fltmc detach %1 O:
fltmc detach %1 P:
fltmc detach %1 Q:
fltmc detach %1 R:
fltmc detach %1 S:
fltmc detach %1 T:
fltmc detach %1 U:
fltmc detach %1 V:
fltmc detach %1 W:
fltmc detach %1 X:
fltmc detach %1 Y:
fltmc detach %1 Z:
fltmc detach %1 \Device\Mup
fltmc detach %1 \Device\NamedPipe
fltmc unload %1
sc stop %1
exit /b 0

:ProcessesAll_StopForce
:: Subroutine for killing all Sophos processes by force
(taskkill /T /F /IM "sweepupdate.exe" /IM "sweepnet.exe" /IM "backgroundscanclient.exe" /IM "sav32cli.exe" /IM "savcleanupservice.exe" /IM "savmain.exe" /IM "savprogress.exe" /IM "savproxy.exe" /IM "sdcdevcon.exe" /IM "wscclient.exe" /IM "clientmrinit.exe" /IM "emlibupdateagentnt.exe" /IM "almon.exe" /IM "agentapi.exe" /IM "autoupdateagentnt.exe" /IM "agentasst.exe" /IM "alupdate.exe" /IM "scfmanager.exe" /IM "SCFService.exe" /IM "spa.exe" /IM "SntpService.exe" /IM "SSPService.exe" /IM "ssp.exe" /IM "SAVAdminService.exe" /IM "SavService.exe" /IM "sdcservice.exe" /IM "Safestore.exe" /IM "Safestore64.exe" /IM "swc_service.exe" /IM "swi_filter.exe" /IM "swi_service.exe" /IM "swi_update.exe" /IM "swi_update_64.exe" /IM "swi_fc.exe" /IM "swi_*" /IM "Health.exe" /IM "McsAgent.exe" /IM "McsClient.exe" /IM "Heartbeat.exe" /IM "SophosFS.exe" /IM "Sophos UI.exe" /IM "ManagementAgentNT.exe" /IM "Clean.exe" /IM "ALsvc.exe" /IM "SEDService.exe" /IM "RouterNT.exe" /IM "UpdateCacheService.exe" /IM "SUMService.exe" /IM "CertificationManagerServiceNT.exe" /IM "SophosADSyncService.exe" /IM "SDRService.exe" /IM "SophosFIMService.exe" /IM "Sophos.FrontEnd.Service.exe" /IM "MgntSvc.exe" /IM "PatchEndpointCommunicator.exe" /IM "PatchEndpointOrchestrator.exe" /IM "PatchServerCommunicator.exe" /IM "Sophos.PolicyEvaluation.Service.exe" /IM "SavexSrvc.exe" /IM "SavexWebAgent.exe" /IM "MMRot.exe" /IM "PMContExtrSvc.exe" /IM "PMEVizsla.exe" /IM "PMScanner.exe" /IM "SGN_MasterServicen.exe" /IM "SophosADSyncService.exe" /IM "Sophos*")2> nul
for /f "tokens=5" %%a in ('dir /S "C:\Program Files\Sophos\*.exe" ^| find "/"') do @(taskkill /T /F /IM "%%~a"2> nul)
for /f "tokens=5" %%a in ('dir /S "C:\Program Files\Common Files\Sophos\*.exe" ^| find "/"') do @(taskkill /T /F /IM "%%~a"2> nul)
for /f "tokens=5" %%a in ('dir /S "C:\Program Files (x86)\Sophos\*.exe" ^| find "/"') do @(taskkill /T /F /IM "%%~a"2> nul)
for /f "tokens=5" %%a in ('dir /S "C:\Program Files (x86)\Common Files\Sophos\*.exe" ^| find "/"') do @(taskkill /T /F /IM "%%~a"2> nul)
for /f "tokens=5" %%a in ('dir /S "C:\ProgramData\Sophos\*.exe" ^| find "/"') do @(taskkill /T /F /IM "%%~a"2> nul)
exit /b 0



:: ----------------------------- SCRIPTS -----------------------------

:PoShScript
echo Function Register-FileToDelete {>"%~dp0Register-FileToDelete.ps1"
echo     ^<#>>"%~dp0Register-FileToDelete.ps1"
echo         .SYNOPSIS>>"%~dp0Register-FileToDelete.ps1"
echo             Registers a file/s or folder/s for deletion after a reboot.>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo         .DESCRIPTION>>"%~dp0Register-FileToDelete.ps1"
echo             Registers a file/s or folder/s for deletion after a reboot.>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo         .PARAMETER Source>>"%~dp0Register-FileToDelete.ps1"
echo             Collection of Files/Folders which will be marked for deletion after a reboot>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo         .NOTES>>"%~dp0Register-FileToDelete.ps1"
echo             Name: Register-FileToDelete>>"%~dp0Register-FileToDelete.ps1"
echo             Author: Boe Prox>>"%~dp0Register-FileToDelete.ps1"
echo             Created: 28 SEPT 2013>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo         .EXAMPLE>>"%~dp0Register-FileToDelete.ps1"
echo             Register-FileToDelete -Source 'C:\Users\Administrators\Desktop\Test.txt'>>"%~dp0Register-FileToDelete.ps1"
echo             True>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo             Description>>"%~dp0Register-FileToDelete.ps1"
echo             ----------->>"%~dp0Register-FileToDelete.ps1"
echo             Marks the file Test.txt for deletion after a reboot.>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo         .EXAMPLE>>"%~dp0Register-FileToDelete.ps1"
echo             Get-ChildItem -File -Filter *.txt ^| Register-FileToDelete -WhatIf>>"%~dp0Register-FileToDelete.ps1"
echo             What if: Performing operation ^"Mark for deletion^" on Target ^"C:\Users\Administrator\Des>>"%~dp0Register-FileToDelete.ps1"
echo             ktop\SQLServerReport.ps1.txt^".>>"%~dp0Register-FileToDelete.ps1"
echo             What if: Performing operation ^"Mark for deletion^" on Target ^"C:\Users\Administrator\Des>>"%~dp0Register-FileToDelete.ps1"
echo             ktop\test.txt^".>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo             Description>>"%~dp0Register-FileToDelete.ps1"
echo             ----------->>"%~dp0Register-FileToDelete.ps1"
echo             Uses a WhatIf switch to show what files would be marked for deletion.>>"%~dp0Register-FileToDelete.ps1"
echo     #^>>>"%~dp0Register-FileToDelete.ps1"
echo     [cmdletbinding(>>"%~dp0Register-FileToDelete.ps1"
echo         SupportsShouldProcess = $True>>"%~dp0Register-FileToDelete.ps1"
echo     )]>>"%~dp0Register-FileToDelete.ps1"
echo     Param (>>"%~dp0Register-FileToDelete.ps1"
echo         [parameter(ValueFromPipeline=$True,>>"%~dp0Register-FileToDelete.ps1"
echo                   ValueFromPipelineByPropertyName=$True)]>>"%~dp0Register-FileToDelete.ps1"
echo         [Alias('FullName','File','Folder')]>>"%~dp0Register-FileToDelete.ps1"
echo         $Source = 'C:\users\Administrator\desktop\test.txt'    >>"%~dp0Register-FileToDelete.ps1"
echo     )>>"%~dp0Register-FileToDelete.ps1"
echo     Begin {>>"%~dp0Register-FileToDelete.ps1"
echo         Try {>>"%~dp0Register-FileToDelete.ps1"
echo             $null = [File]>>"%~dp0Register-FileToDelete.ps1"
echo         } Catch { >>"%~dp0Register-FileToDelete.ps1"
echo             Write-Verbose 'Compiling code to create type'   >>"%~dp0Register-FileToDelete.ps1"
echo             Add-Type ^@^">>"%~dp0Register-FileToDelete.ps1"
echo             using System;>>"%~dp0Register-FileToDelete.ps1"
echo             using System.Collections.Generic;>>"%~dp0Register-FileToDelete.ps1"
echo             using System.Linq;>>"%~dp0Register-FileToDelete.ps1"
echo             using System.Text;>>"%~dp0Register-FileToDelete.ps1"
echo             using System.Runtime.InteropServices;>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo             public class Posh>>"%~dp0Register-FileToDelete.ps1"
echo             {>>"%~dp0Register-FileToDelete.ps1"
echo                 public enum MoveFileFlags>>"%~dp0Register-FileToDelete.ps1"
echo                 {>>"%~dp0Register-FileToDelete.ps1"
echo                     MOVEFILE_REPLACE_EXISTING           = 0x00000001,>>"%~dp0Register-FileToDelete.ps1"
echo                     MOVEFILE_COPY_ALLOWED               = 0x00000002,>>"%~dp0Register-FileToDelete.ps1"
echo                     MOVEFILE_DELAY_UNTIL_REBOOT         = 0x00000004,>>"%~dp0Register-FileToDelete.ps1"
echo                     MOVEFILE_WRITE_THROUGH              = 0x00000008,>>"%~dp0Register-FileToDelete.ps1"
echo                     MOVEFILE_CREATE_HARDLINK            = 0x00000010,>>"%~dp0Register-FileToDelete.ps1"
echo                     MOVEFILE_FAIL_IF_NOT_TRACKABLE      = 0x00000020>>"%~dp0Register-FileToDelete.ps1"
echo                 }>>"%~dp0Register-FileToDelete.ps1"
echo.>>"%~dp0Register-FileToDelete.ps1"
echo                 [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]>>"%~dp0Register-FileToDelete.ps1"
echo                 static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);>>"%~dp0Register-FileToDelete.ps1"
echo                 public static bool MarkFileDelete (string sourcefile)>>"%~dp0Register-FileToDelete.ps1"
echo                 {>>"%~dp0Register-FileToDelete.ps1"
echo                     bool brc = false;>>"%~dp0Register-FileToDelete.ps1"
echo                     brc = MoveFileEx(sourcefile, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);          >>"%~dp0Register-FileToDelete.ps1"
echo                     return brc;>>"%~dp0Register-FileToDelete.ps1"
echo                 }>>"%~dp0Register-FileToDelete.ps1"
echo             }>>"%~dp0Register-FileToDelete.ps1"
echo ^"^@>>"%~dp0Register-FileToDelete.ps1"
echo         }>>"%~dp0Register-FileToDelete.ps1"
echo     }>>"%~dp0Register-FileToDelete.ps1"
echo     Process {>>"%~dp0Register-FileToDelete.ps1"
echo         ForEach ($item in $Source) {>>"%~dp0Register-FileToDelete.ps1"
echo             Write-Verbose ('Attempting to resolve {0} to full path if not already' -f $item)>>"%~dp0Register-FileToDelete.ps1"
echo             $item = (Resolve-Path -Path $item).ProviderPath>>"%~dp0Register-FileToDelete.ps1"
echo             If ($PSCmdlet.ShouldProcess($item,'Mark for deletion')) {>>"%~dp0Register-FileToDelete.ps1"
echo                 If (-NOT [Posh]::MarkFileDelete($item)) {>>"%~dp0Register-FileToDelete.ps1"
echo                     Try {>>"%~dp0Register-FileToDelete.ps1"
echo                         Throw (New-Object System.ComponentModel.Win32Exception)>>"%~dp0Register-FileToDelete.ps1"
echo                     } Catch {Write-Warning $_.Exception.Message}>>"%~dp0Register-FileToDelete.ps1"
echo                 }>>"%~dp0Register-FileToDelete.ps1"
echo             }>>"%~dp0Register-FileToDelete.ps1"
echo         }>>"%~dp0Register-FileToDelete.ps1"
echo     }>>"%~dp0Register-FileToDelete.ps1"
echo }>>"%~dp0Register-FileToDelete.ps1"
exit /b 0
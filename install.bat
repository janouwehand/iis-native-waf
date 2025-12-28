%windir%\system32\inetsrv\appcmd install module /name:SimpleWaf /image:C:\IISModules\SimpleWaf.dll
cmd setx SIMPLE_WAF_LOG_PATH "C:\IISModules\SimpleWaf.txt" /M
pause

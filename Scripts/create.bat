cd %~dp0
cd ..\
copy airhv.sys %SystemRoot%\system32\drivers\airhv.sys
copy HyperHideDrv.sys %SystemRoot%\system32\drivers\airhv.sys
sc create airhv type= Kernel binpath= %SystemRoot%\system32\drivers\airhv.sys
sc create HyperHideDrv type= Kernel binpath= %SystemRoot%\system32\drivers\HyperHideDrv.sys
pause

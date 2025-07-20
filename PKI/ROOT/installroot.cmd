@echo off
chcp 65001 > nul
setlocal

:: 检查管理员权限
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :ADMIN_PRIVILEGES
) else (
    echo 请求管理员权限...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~0", "%~dp0", "", "runas", 1 >> "%temp%\getadmin.vbs"
    call "%temp%\getadmin.vbs"
    ::del ".\getadmin.vbs"
    exit /b
)

:: 将管理员模式下的运行目录切换到当前目录
if "%~1" == "" (
	cd %~1
)

:ADMIN_PRIVILEGES
:: 这里是需要管理员权限的代码

echo 当前目录：%~1
echo 正在以管理员身份运行...

:: 你的管理员权限代码放在这里
:: 例如：
:: net start "服务名"
:: sc config 服务名 start= auto
@echo off
chcp 65001 > nul
setlocal

:: 检查管理员权限
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :ADMIN_PRIVILEGES
) else (
    echo 请求管理员权限...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~0", "%~dp0", "", "runas", 1 >> "%temp%\getadmin.vbs"
    call "%temp%\getadmin.vbs"
    ::del ".\getadmin.vbs"
    exit /b
)

:: 将管理员模式下的运行目录切换到当前目录
if "%~1" == "" (
	cd %~1
)

:ADMIN_PRIVILEGES
:: 这里是需要管理员权限的代码

echo 当前目录：%~1
echo 正在以管理员身份运行...

:: 你的管理员权限代码放在这里
:: 例如：

::需要鼠标右键单击 使用管理员模式运行
::作用安装root.crt到系统可信证书库
certutil -addstore -f Root %~dp0root.crt
::安装root.crt到系统第三方可信证书库
certutil -addstore -f AuthRoot %~dp0root.crt
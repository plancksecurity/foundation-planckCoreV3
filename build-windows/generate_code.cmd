@ECHO OFF

:: The script is located in ...\pEpForWindowsAdapterSolution\pEpEngine\build-windows\
SET current_directory=%~dp0

:: Engine directory is ...\pEpForWindowsAdapterSolution\pEpEngine\
SET engine_directory=%current_directory:~0,-14%

:: YML2 directory is ...\pEpForWindowsAdapterSolution\yml2\
SET yml2_directory=%engine_directory:~0,-11%\yml2

:: Generate code in ...\pEpEngine\sync
PUSHD %engine_directory%\sync

IF NOT EXIST generated MKDIR generated

ECHO py "%yml2_directory%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
py "%yml2_directory%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%yml2_directory%\yml2proc" -E utf-8 -y gen_codec.ysl2 distribution.fsm
py "%yml2_directory%\yml2proc" -E utf-8 -y gen_codec.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%yml2_directory%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
py "%yml2_directory%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%yml2_directory%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
py "%yml2_directory%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%yml2_directory%\yml2proc" -E utf-8 -y gen_messages.ysl2 distribution.fsm
py "%yml2_directory%\yml2proc" -E utf-8 -y gen_messages.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%yml2_directory%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm
py "%yml2_directory%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%yml2_directory%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
py "%yml2_directory%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

XCOPY /y generated\*.asn1 ..\asn.1\
XCOPY /y generated\*.c ..\src\
XCOPY /y generated\*.h ..\src\

CD %engine_directory%\asn.1

DEL *.h
DEL *.c

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keysync.asn1 sync.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keyreset.asn1 distribution.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end

DEL *-sample.c

CD %engine_directory%\..
RD /S/Q pEp
MKDIR pEp
XCOPY pEpEngine\src\*.h pEp\ /Y/F/I


:end

POPD
EXIT /B %ERRORLEVEL%
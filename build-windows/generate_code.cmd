@ECHO OFF

:: The script is located in ...\pEpEngine\build-windows\
SET current_directory=%~dp0
SET engine_directory=%current_directory:~0,-14%
ECHO %engine_directory%
PUSHD %engine_directory%\sync

IF NOT EXIST generated MKDIR generated

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 distribution.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 distribution.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

XCOPY /y generated\*.asn1 ..\asn.1\
XCOPY /y generated\*.c ..\src\
XCOPY /y generated\*.h ..\src\

CD %engine_directory%\asn.1

DEL *.h
DEL *.c

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keysync.asn1 sync.asn1
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)
..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keyreset.asn1 distribution.asn1
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)

DEL *-sample.c

CD %engine_directory%\..
RD /S/Q pEp
MKDIR pEp
XCOPY pEpEngine\src\*.h pEp\ /Y/F/I


:end

POPD
IF %ERRORLEVEL% NEQ 0 EXIT /B 1
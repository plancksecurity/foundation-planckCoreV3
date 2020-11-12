@ECHO OFF
PUSHD .
SET pwd=%cd%
CD %pwd%\sync

IF NOT EXIST generated MKDIR generated

ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)
ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 distribution.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)
ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)
ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)
ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 distribution.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)
ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)
ECHO py "%YML_PATH%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 (
	POPD
	EXIT /B 1
	)

xcopy /y generated\*.asn1 ..\asn.1\
xcopy /y generated\*.c ..\src\
xcopy /y generated\*.h ..\src\

CD %pwd%\asn.1

DEL *.h
DEL *.c

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keysync.asn1 sync.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keyreset.asn1 distribution.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end

DEL *-sample.c

CD %pwd%\..
RD /S/Q pEp
MKDIR pEp
XCOPY pEpEngine\src\*.h pEp\ /Y/F/I

POPD

::@ECHO OFF

:: The script is located in ...\pEpForWindowsAdapterSolution\PlanckCoreV3\build-windows\
SET current_directory=%~dp0

:: Engine directory is ...\pEpForWindowsAdapterSolution\PlanckCoreV3\
SET engine_directory=%current_directory:~0,-15%
ECHO %engine_directory%

SET YML2PROC=%PY% %PYTHON_SCRIPTS%\yml2proc

:: Create the system.db
PUSHD %engine_directory%\db
CALL make_systemdb %1
IF NOT EXIST "%ProgramData%\pEp" MKDIR "%ProgramData%\pEp"
DEL /F /Q "%ProgramData%\pEp\system.db"
MOVE system.db "%ProgramData%\pEp\system.db"

:: Generate code in ...\PlanckCoreV3\codegen
CD ..\codegen

:: Make sure YML2 is installed
%PY% -m pip install --upgrade pip
%PY% -m pip install wheel
%PY% -m pip install git+https://github.com/plancksecurity/foundation-yml2.git@a5a1378

:: Generate code in ...\PlanckCoreV3\codegen
CD ..\..\PlanckCoreV3\codegen

:: Generate the Sync code
IF NOT EXIST generated MKDIR generated

ECHO %YML2PROC% -E utf-8 -y gen_actions.ysl2 sync.fsm
ECHO define actfile = "./sync.act"; | %YML2PROC% - gen_actions.ysl2 | %YML2PROC% -X - sync.fsm -o sync.act.gen
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO %YML2PROC% -E utf-8 -y gen_codec.ysl2 distribution.fsm
%YML2PROC% -E utf-8 -y gen_codec.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO %YML2PROC% -E utf-8 -y gen_codec.ysl2 sync.fsm
%YML2PROC% -E utf-8 -y gen_codec.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO %YML2PROC% -E utf-8 -y gen_messages.ysl2 sync.fsm
%YML2PROC% -E utf-8 -y gen_messages.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO %YML2PROC% -E utf-8 -y gen_messages.ysl2 distribution.fsm
%YML2PROC% -E utf-8 -y gen_messages.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO %YML2PROC% -E utf-8 -y gen_message_func.ysl2 sync.fsm
%YML2PROC% -E utf-8 -y gen_message_func.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO %YML2PROC% -E utf-8 -y gen_statemachine.ysl2 sync.fsm
%YML2PROC% -E utf-8 -y gen_statemachine.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO %YML2PROC% -E utf-8 -y gen_messages.ysl2 storage.fsm
%YML2PROC% -E utf-8 -y gen_messages.ysl2 storage.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

XCOPY /y generated\*.asn1 ..\asn.1\
XCOPY /y generated\*.c ..\src\
XCOPY /y generated\*.h ..\src\

CD %engine_directory%\asn.1

DEL *.h
DEL *.c

rem DISTRIBUTION = distribution keyreset managedgroup exploration echo
rem SYNC  = sync keysync trustsync groupsync
rem STORAGE = storage messagestorage

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 sync.asn1 keysync.asn1 trustsync.asn1 groupsync.asn1 distribution.asn1 keyreset.asn1 managedgroup.asn1 exploration.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end
type nul >> "Sync.c"
..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 distribution.asn1 keyreset.asn1 managedgroup.asn1 exploration.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end
type nul >> "Distribution.c"
del /q ReceiverRating.c.* ReceiverRating.h.*
..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto storage.asn1 messagestorage.asn1 pEp.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end
type nul >> "Storage.c"
..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 message.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end
type nul >> "ASN1Message.c"



DEL *-sample.c

CD %engine_directory%\..
MKDIR %1\include
MKDIR %1\include\pEp
MKDIR %1\include\pEp\internal
XCOPY PlanckCoreV3\src\*.h %1\include\pEp\ /Y/F/I
XCOPY libPlanckWrapper\src\*.h %1\include\pEp\ /Y/F/I
XCOPY libPlanckWrapper\src\*.hh %1\include\pEp\ /Y/F/I
XCOPY libPlanckWrapper\src\*.hxx %1\include\pEp\ /Y/F/I
XCOPY libPlanckWrapper\src\internal\*.* %1\include\pEp\internal /Y/F/I

:end

POPD
EXIT /B %ERRORLEVEL%

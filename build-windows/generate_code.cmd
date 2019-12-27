pushd .
set pwd=%cd%
cd %pwd%\sync

if not exist generated mkdir generated

py "%YML_PATH%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 distribution.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
py "%YML_PATH%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm

xcopy /y generated\*.asn1 ..\asn.1\
xcopy /y generated\*.c ..\src\
xcopy /y generated\*.h ..\src\

cd %pwd%\asn.1

del *.h
del *.c

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keysync.asn1 sync.asn1
..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keyreset.asn1 distribution.asn1

del *-sample.c

cd %pwd%\..
if not exist pEp mklink /d pEp pEpEngine\src

popd

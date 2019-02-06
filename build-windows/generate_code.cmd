pushd .
cd %1\sync

if not exist generated mkdir generated

python "%YML_PATH%\yml2proc" -E utf-8 -y gen_actions.ysl2 sync.fsm
python "%YML_PATH%\yml2proc" -E utf-8 -y gen_statemachine.ysl2 sync.fsm
python "%YML_PATH%\yml2proc" -E utf-8 -y gen_codec.ysl2 sync.fsm
python "%YML_PATH%\yml2proc" -E utf-8 -y gen_messages.ysl2 sync.fsm
python "%YML_PATH%\yml2proc" -E utf-8 -y gen_message_func.ysl2 sync.fsm

xcopy /y generated\*.asn1 ..\asn.1\
xcopy /y generated\*.c ..\src\
xcopy /y generated\*.h ..\src\

cd %1\asn.1

del *.h*
del *.c*

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keysync.asn1 sync.asn1

del *-sample.c

cd %1\..
if not exist pEp mklink /d pEp pEpEngine\src

popd

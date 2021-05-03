# -*- coding: utf-8 -*-
#
# this file is under GNU General Public License 3.0
# Copyleft 2017-2021, p≡p foundation


from transport import *
from multiprocessing import Process


def setup_gnupg(arthome):
    print("using arthome", arthome)
    os.environ["HOME"] = os.path.join(mydir, arthome)
    os.environ["GNUPGHOME"] = os.path.join(mydir, arthome, 'gnupg')
    os.chdir(os.path.join(mydir, arthome))


def assert_gnupg():
    assert os.environ["GNUPGHOME"] != ""


mydir = os.path.dirname(os.path.realpath(__file__))


ALICE = "test1@peptest.ch",  "Alice One"
BOB = "test2@peptest.ch", "Bob Two"


def Me(who):
    assert_gnupg() ; import pEp
    me = pEp.Identity(*who)
    pEp.myself(me)
    return me

def You(who):
    assert_gnupg() ; import pEp
    you = pEp.Identity(*who)
    you.update()
    return you


def test_handshake():

    def process1():
        print("process1 starting")
        setup_gnupg("test1") ; import pEp
        me = Me(ALICE)
        you = You(BOB)

        msg = pEp.Message(1, me)
        msg.to = [you]
        msg.shortmsg = "Subject line"
        msg.longmsg = "Message Text\n"

        enc = msg.encrypt()
        send_message("test2", str(enc))

        txt = wait_for_message()
        enc = pEp.Message(txt)
        assert enc.from_.address == "test2@peptest.ch"
        inc, keys, rating, flags = enc.decrypt()
        assert rating == 6

        msg = pEp.Message(1, me)
        msg.to = [you]
        msg.shortmsg = "Subject line complete"
        msg.longmsg = "Message Text complete\n"

        enc = msg.encrypt()
        send_message("test2", str(enc))
        print("process1 finishing")

    def process2():
        print("process2 starting")
        setup_gnupg("test2") ; import pEp
        me = Me(BOB)
        you = You(ALICE)

        txt = wait_for_message()
        msg = pEp.Message(txt)
        msg.decrypt()
        assert msg.from_.address == you.address

        out = pEp.Message(1, me)
        out.to = [you]
        out.shortmsg = "Subject Back"
        out.longmsg = "Text Back\n"

        enc = out.encrypt()
        send_message("test1", str(enc))

        txt = wait_for_message()
        msg = pEp.Message(txt)
        msg.decrypt()
        assert msg.from_.address == you.address
        print("process2 finishing")

    p1 = Process(target=process1, daemon=True)
    p2 = Process(target=process2, daemon=True)
    p1.start()
    p2.start()
    p1.join()
    p2.join()
    assert p2.exitcode == 0
    assert p1.exitcode == 0

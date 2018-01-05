# -*- coding: utf-8 -*-

# this file is under GNU General Public License 3.0
# Copyleft 2017, p≡p foundation


from transport import *


def setup_gnupg():
    assert os.environ["GNUPGHOME"] != ""


mydir = os.path.dirname(os.path.realpath(__file__))


class Test1:

    def setup_method(self):
        arthome = "test1"

        os.environ["HOME"] = os.path.join(mydir, arthome)
        os.environ["GNUPGHOME"] = os.path.join(mydir, arthome, '.gnupg')

        os.chdir(os.path.join(mydir, arthome))

    @property
    def me(self):
        # because of flaws of py.test these two statements are necessary
        setup_gnupg()   # work around a bug with initializing os.environ
        import pEp      # after that import pEp module, not before

        i = pEp.Identity()
        i.address = "test1@peptest.ch"
        i.username = "Alice One"
        pEp.myself(i)
        return i

    @property
    def you(self):
        setup_gnupg() ; import pEp

        i = pEp.Identity()
        i.address = "test2@peptest.ch"
        i.username = "Bob Two"
        pEp.update_identity(i)
        return i

    def test_handshake(self):
        setup_gnupg() ; import pEp

        msg = pEp.Message(1)
        msg.from_ = self.me
        msg.to = [self.you]
        msg.shortmsg = "Subject line"
        msg.longmsg = "Message Text\n"

        enc = msg.encrypt()
        send_message("test2", str(enc))

        txt = wait_for_message()
        enc = pEp.Message(txt)
        assert enc.from_.address == "test2@peptest.ch"
        inc, keys, rating, consumed, flags = enc.decrypt()
        assert rating == 6

        msg = pEp.Message(1)
        msg.from_ = self.me
        msg.to = [self.you]
        msg.shortmsg = "Subject line complete"
        msg.longmsg = "Message Text complete\n"

        enc = msg.encrypt()
        send_message("test2", str(enc))

class Test2:

    def setup_method(self):
        arthome = "test2"

        os.environ["HOME"] = os.path.join(mydir, arthome)
        os.environ["GNUPGHOME"] = os.path.join(mydir, arthome, '.gnupg')

        os.chdir(os.path.join(mydir, arthome))

    @property
    def me(self):
        # because of flaws of py.test these two statements are necessary
        setup_gnupg()   # work around a bug with initializing os.environ
        import pEp      # after that import pEp module, not before

        i = pEp.Identity()
        i.address = "test2@peptest.ch"
        i.username = "Bob Two"
        pEp.myself(i)
        return i

    @property
    def you(self):
        setup_gnupg() ; import pEp

        i = pEp.Identity()
        i.address = "test1@peptest.ch"
        i.username = "Alice One"
        pEp.update_identity(i)
        return i

    def test_handshake(self):
        setup_gnupg() ; import pEp

        txt = wait_for_message()
        msg = pEp.Message(txt)
        msg.decrypt()
        assert msg.from_.address == self.you.address

        out = pEp.Message(1)
        out.from_ = self.me
        out.to = [self.you]
        out.shortmsg = "Subject Back"
        out.longmsg = "Text Back\n"

        enc = out.encrypt()
        send_message("test1", str(enc))

        txt = wait_for_message()
        msg = pEp.Message(txt)
        msg.decrypt()
        assert msg.from_.address == self.you.address


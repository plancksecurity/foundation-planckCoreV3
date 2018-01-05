# -*- coding: utf-8 -*-

# this file is under GNU General Public License 3.0
# Copyleft 2017, p≡p foundation


from transport import *


class Test1:

    def setup_class(self):
        arthome = "test1"

        self.mydir = os.path.abspath(os.path.curdir)

        os.environ["HOME"] = os.path.join(self.mydir, arthome)
        os.environ["GNUPGHOME"] = os.path.join(self.mydir, arthome, '.gnupg')

        os.chdir(os.path.join(self.mydir, arthome))

    @property
    def me(self):
        # because of flaws of py.test these two lines are necessary
        assert os.environ["GNUPGHOME"] != ""
        import pEp

        i = pEp.Identity()
        i.address = "test1@peptest.ch"
        i.username = "Alice One"
        pEp.myself(i)
        return i

    @property
    def you(self):
        assert os.environ["GNUPGHOME"] != ""
        import pEp

        i = pEp.Identity()
        i.address = "test2@peptest.ch"
        i.username = "Bob Two"
        pEp.update_identity(i)
        return i

    def test_send_message(self):
        assert os.environ["GNUPGHOME"] != ""
        import pEp

        msg = pEp.Message()
        msg.from_ = self.me
        msg.to = [self.you]
        msg.shortmsg = "Subject line"
        msg.longmsg = "Message Text\n"

        enc = msg.encrypt()
        send_message("test2", str(enc))


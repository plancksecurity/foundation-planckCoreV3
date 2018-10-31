import argparse
import gnupg
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("pattern")
parser.add_argument("--priv", "-p", help="also delete associated private keys", action='store_true')

args = parser.parse_args()

homedir = os.path.join(os.path.expanduser('~'),"gnupg")
print("GNUPGHOME=" + homedir + "\n")

try:
    gpg = gnupg.GPG(gnupghome=homedir) 
except TypeError:
    gpg = gnupg.GPG(homedir=homedir)

if not args.pattern:
    raise Exception("No pattern? How'd you do that?")
    
public_keys = gpg.list_keys(keys=args.pattern) # same as gpg.list_keys(False)

for key in public_keys:
    print("Deleting keys...\n")
    for uid in key['uids']:
        print(uid + " ")
    print(key['fingerprint'] + "\n")
    if args.priv:
        gpg.delete_keys(key['fingerprint'], True)
    gpg.delete_keys(key['fingerprint'])

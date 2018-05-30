import argparse
import gnupg
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("num_keys", type=int)
parser.add_argument("real_name_prefix")
parser.add_argument("email_address_prefix")
parser.add_argument("output_root", help="root of where to stick the keys (keys go into pub/ and priv/ accordingly)")
parser.add_argument("--no_suffix", "-x", help="Use name and email address as is - do not create incremental ones based on the input", action='store_true')
parser.add_argument("--hgadd", "-a", help="hg add the created keyfiles", action='store_true')

args = parser.parse_args()

pub_path = os.path.join(args.output_root, "pub")
priv_path = os.path.join(args.output_root, "priv")

homedir = os.path.join(os.path.expanduser('~'),".gnupg")
print("GNUPGHOME=" + homedir + "\n")

try:
    gpg = gnupg.GPG(gnupghome=homedir) 
except TypeError:
    gpg = gnupg.GPG(homedir=homedir)

name = args.real_name_prefix
email = args.email_address_prefix
    
suffix = not args.no_suffix

name_prefix = args.real_name_prefix + " "     
e_split = args.email_address_prefix.split('@')
e_split_len = len(e_split)

if (e_split_len > 2):
    for j in range(e_split_len - 1):
        email_0 = email_0 + e_split[j] + "@"
    email_0 = email_0 + _ + i_str + e_split[e_split_len - 1]    
    email_1 = e_split_len[e_split_len - 1]
    e_split = [email_0, email_1]
    e_split_len = 2
elif (e_split_len == 0):
        email_0 = "doge"    
        email_1 = "dogepile.me"
        e_split = [email_0, email_1]
        e_split_len = 2
    
num_keys = args.num_keys
    
for i in range(num_keys):
    i_str = str(i)

    if suffix:
        
        name = name_prefix + i_str
        
        if e_split_len == 1:
            email = e_split[0] + "_" + i_str
        elif e_split_len == 2:
            email = e_split[0] + "_" + i_str + "@" + e_split[1]

    print("Generating key data for " + name + " " + email + "\n")
    input_data = gpg.gen_key_input(key_type="RSA", key_length=2048, subkey_type="RSA", subkey_length=2048, expire_date=0, name_real=name, name_email=email, password="")
    if not input_data:
        raise Exception('Input data not created in iteration ' + str(i))
    
    print(input_data)
    key = None
    key = gpg.gen_key(input_data)
    if not key:
        raise Exception('Key not created in iteration ' + str(i))
    pubkey = None
    privkey = None
    
    fpr = key.fingerprint
    print("Generated " + fpr)
    key_filename_prefix = e_split[0] + "_" + i_str + "-0x" + fpr[-8:] + "_"

    
    pubkey = gpg.export_keys(fpr)
    privkey = gpg.export_keys(fpr, True, passphrase="")

    pubkey_filename = os.path.join(pub_path, key_filename_prefix + "pub.asc")
    privkey_filename = os.path.join(priv_path, key_filename_prefix + "priv.asc")    
    
    # Write to file
    pubkey_file = open(pubkey_filename,'w')
    pubkey_file.write(pubkey)
    pubkey_file.close()
    privkey_file = open(privkey_filename,'w')    
    privkey_file.write(privkey)
    privkey_file.close()
        
    # Delete keys from keyring
    gpg.delete_keys(fpr, True, passphrase="") # True => private keys
    gpg.delete_keys(fpr)

    if (args.hgadd):
        subprocess.run(["hg", "add", pubkey_filename])
        subprocess.run(["hg", "add", privkey_filename])

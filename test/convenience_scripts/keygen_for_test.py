# Modified to just do the gpg stuff directly. Not really fully tested, so use at your own risk.
# this is only intended to do stuff quickly for the test suite.
import argparse
import os
import subprocess

from subprocess import Popen, PIPE

class ccodes:
    Red = u"\u001b[31m" 
    Green = u"\u001b[32m"
    Yellow = u"\u001b[33m"
    Blue = u"\u001b[34m"
    Magenta = u"\u001b[35m"
    Cyan = u"\u001b[36m"
    White = u"\u001b[37m"
    BrightRed = u"\u001b[31;1m"
    BrightGreen = u"\u001b[32;1m"
    BrightYellow = u"\u001b[33;1m"
    BrightBlue = u"\u001b[34;1m"
    BrightMagenta = u"\u001b[35;1m"
    BrightCyan = u"\u001b[36;1m"
    BrightWhite = u"\u001b[37;1m"    
    RESET = u"\u001b[0m"
    
def color_str(color, plaintext):
    return (color + plaintext + ccodes.RESET)

def get_name_email(num, name_pre, local, domain):
    num_str = str(num)

    name = name_pre + num_str
    
    if domain == None:
        email = local + "_" + num_str
    else:
        email = local + "_" + num_str + "@" + domain

    return name, email

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

homedir = os.path.join(os.path.expanduser('~'),"gnupg")
print("GNUPGHOME=" + homedir + "\n")

genkey_path = os.path.join(os.getcwd(), "genkey")


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
    
genkey_file = open(genkey_path, 'w');
    
for i in range(num_keys):
    if suffix:
        name_email = get_name_email(i, name_prefix, e_split[0], None if (e_split_len == 1) else e_split[1])  
        name = name_email[0]
        email = name_email[1]    

    print("Generating key data for " + name + " " + email + "\n")

    genkey_file.write("Key-Type: default\n");
    genkey_file.write("Key-Length: 4096\n");
    genkey_file.write("Subkey-Type: default\n");
    genkey_file.write("Subkey-Length: 4096\n");
    genkey_file.write("Name-Real: " + name + "\n");
    genkey_file.write("Name-Comment: Test Keys for pEp\n");
    genkey_file.write("Name-Email: " + email + "\n");
    genkey_file.write("Expire-Date: 0\n");
    genkey_file.write("%no-protection\n");
    genkey_file.write("%commit\n");
    genkey_file.write("\n");
    
genkey_file.close()    

#os.system("gpg --gen-key --with-fingerprint --batch genkey");

fpr_list = []

process = Popen(["gpg", "--gen-key", "--batch", "genkey"], stderr=PIPE)

print()
while True:
    line = process.stderr.readline()
    if not line:
        break
    line_str = line.decode('utf-8').strip()
    
    if line_str.endswith(".rev'"):
        fpr_list.append(line_str[-45:-5])
        print(color_str(ccodes.BrightYellow, ("All good, Created " + line_str[-45:-5])));
        
# Now let's export them and delete those bastards
i = 0;
for fpr in fpr_list:
    i_str = str(i)

    key_filename_prefix = e_split[0] + "_" + i_str + "-0x" + fpr[-8:] + "_"
            
    print(color_str(ccodes.BrightGreen, ("Exporting " + fpr)))

    pubkey_filename = os.path.join(pub_path, key_filename_prefix + "pub.asc")
    privkey_filename = os.path.join(priv_path, key_filename_prefix + "priv.asc")    

    pubkey_file = open(pubkey_filename,'w')    
    exp_proc = subprocess.call(["gpg", "--export", "-a", fpr], stdout=pubkey_file)
    pubkey_file.close()    

    privkey_file = open(privkey_filename,'w')    
    exp_proc = subprocess.call(["gpg", "--export-secret-keys", "-a", fpr], stdout=privkey_file)
    privkey_file.close()    

    print(color_str(ccodes.BrightGreen, ("Deleting " + fpr)))
    delproc = subprocess.call(["gpg", "--batch", "--yes", "--delete-secret-keys", fpr])        
    delproc = subprocess.call(["gpg", "--batch", "--delete-key", fpr])        
    i = i + 1
    
    if (args.hgadd):
        subprocess.run(["hg", "add", pubkey_filename])
        subprocess.run(["hg", "add", privkey_filename])

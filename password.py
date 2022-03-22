import subprocess
import sys
import os
import getpass
import base64
import random
import string
from hashlib import sha256

# This script calls to the OpenSSL library (though the openssl executable 
# which must be present on your system)
# Usage: ./password.py [keygen/in/out] [url] [password]

# Global parameters:

# key-length
l = 10
# path to encrypted common pass
common_pass_path = "enc_pass.bin"
lcmd = ["init","out","in","keygen","remove"]

class OpensslError(Exception):
    pass

def encrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    """ Encryption function using a symmetric cipher.
    The passphrase is an str object
    The plaintext is str
    The output is bytes"""

    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-pass', pass_arg, '-pbkdf2']
    plaintext = plaintext.encode('utf-8')    

    result = subprocess.run(args, input=plaintext, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return result.stdout

def decrypt(ciphertext, passphrase, cipher='aes-128-cbc'):
    """ Decryption function using a symmetric cipher.
    The passphrase is an str object
    The ciphertext is str (base64)
    The output is bytes"""

    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-d', '-' + cipher, '-pbkdf2', '-pass', pass_arg]
    # ciphertext = ciphertext.encode('utf-8')

    result = subprocess.run(args, input=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)
    
    return result.stdout.decode()

def hash(domain):
    filename = sha256(domain.encode())
    filename = base64.b64encode(filename.digest()).decode()
    return filename.replace('/','-')

def keygen(l):
    # lchar = list(string.ascii_lowercase) + list(string.ascii_uppercase) + [':','?','$']
    lchar = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ':', '?', '$']
    s = ''
    for i in range(l):
        s += random.choice(lchar)
    return s

def readfile(filename,option="r"):
    f = open(filename,option)
    content = f.read()
    f.close()
    return content

def readpass(domain):
    h = hash(domain)
    hfile = 'passwords/{0}'.format(h)
    f = open(hfile,"rb")
    enc_pass = f.read()
    f.close()
    return enc_pass

def writepass(domain,enc_pass):
    h = hash(domain)
    hfile = 'passwords/{0}'.format(h)
    f = open(hfile,"wb")
    f.write(enc_pass)
    f.close()
    f = open("domains.txt","a")
    f.write(domain+"\n")
    f.close()

def printdomains():
    print("List of all domains:\n")
    with open("domains.txt") as file:
        ldomains = [line.rstrip() for line in file]

    for domain in ldomains:
        print("\t* ", domain)

def authenticate():
    unique_pass = getpass.getpass('Password:')
    if not os.path.exists(common_pass_path):
        sys.exit("No common passphrase found. Please run init command: ./mypassword init")
    else:
        ciphertext = readfile(common_pass_path,"rb")
        try:
            passphrase = decrypt(ciphertext,unique_pass)
            return passphrase
        except:
            sys.exit("Incorrect password!")

def init():
    if os.path.exists(common_pass_path):
        sys.exit("A common password have existsed already. Verify "+common_pass_path)

    unique_pass = getpass.getpass('Please choose a personal password:')
    passphrase_raw = keygen(l)
    passphrase = encrypt(passphrase_raw,unique_pass)
    f = open(common_pass_path,'wb')
    f.write(passphrase)
    f.close()
    sys.exit("Encrypted common passphrase created at "+common_pass_path+". Exit.")

nargs = len(sys.argv)
if nargs == 1:
    sys.exit("Usage: ./mypassword [out/in/keygen]")
elif nargs > 4:
    sys.exit("Incorrect number of arguments!")

command = sys.argv[1]
if command not in listcmd:
    sys.exit("Unaccepted request!")

if command == "init":
    init()

passphrase = authenticate()

if command == "out":
    if nargs == 2:
        printdomains()
    elif nargs == 3:
        domain = sys.argv[2]
        enc_passwd = readpass(domain)
        passwd = decrypt(enc_passwd,passphrase)
        print(passwd)
    else:
        sys.exit("Usage: ./mypassword out [domain]]")
elif command == "in":
    if nargs == 2:
        sys.exit("Usage: ./mypassword in [domain] [password (optional)]")
    else:
        domain = sys.argv[2]
        if nargs == 4:
            passwd = sys.argv[3]
        else: 
            passwd = keygen(l)

        enc_passwd = encrypt(passwd,passphrase)
        writepass(domain,enc_passwd)    
else:
    print("Here is a suggested passpharse:", keygen(l))
    print("If you want to keep it, please write it down somewhere!")

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from termcolor import colored
import pyinputplus as pyip
import getopt, sys

def usage():
    print("usage:\n")
    print(f"$ python {sys.argv[0]} <action> <options>\n")
    print("actions:\n")
    print("\tkeygen\t\t\t\tgeneraiting a key pair")
    print("\tencrypt <options>\t\tencrypting a file")
    print("\tdecrypt <options>\t\tdecrypting a file\n")
    print("options:\n")
    print("\t--key <file name>\t\tfile containing a key")
    print("\t--pass <password>\t\tpassword for the private key")
    print("\t-f <file name>\t\tfile to encrypt/decrypt")
    print("\t-o <output file>\t\toutput file\n")
    print("examples:\n")
    print(f"$ python {sys.argv[0]} keygen\n")
    print(f"$ python {sys.argv[0]} encrypt --key TEST_public.asc -o test.bin -f test.txt\n")
    print(f"$ python {sys.argv[0]} decrypt --key TEST_private.asc -f test.bin --pass 1234\n")
    print()
    sys.exit()


class RSAKeyGenerator():
    def __init__(self, bits=2048, passphrase=None):
        self.key_pair = RSA.generate(bits)
        self.public_key = self.key_pair.publickey().exportKey("PEM")
        self.private_key = self.key_pair.exportKey(format="PEM", passphrase=passphrase)

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key


def set_password() -> str:
    passwd = None
    while True:
        print("Set password:")
        passwd = pyip.inputPassword(colored('> ', 'yellow'))
        if passwd == '':
            passwd = None
            break
        print("Confirm password:")
        passwd_check = pyip.inputPassword(colored('> ', 'yellow'))
        if passwd == passwd_check:
            break
        else:
            print(colored("Sorry, try, again", 'red'))
            continue
    return passwd


def keygen():
    PUBLIC_KEY_FILE = 'public.asc'
    PRIVATE_KEY_FILE = 'private.asc'

    print(colored("[+]", 'magenta') + " Start")
    print(colored("[+]", 'magenta') + " Creating keys")
    passwd = set_password()
    print(colored("[*]", 'blue') + ' Generating key pair...', end=' ')
    keys = RSAKeyGenerator(passphrase=passwd)
    print(colored("OK", 'green'))
    print(colored("[*]", 'blue') + " Exporting public key...", end=' ')
    public_key = keys.get_public_key()
    print(colored("OK", 'green'))
    print(colored("[*]", 'blue') + " Exporting private key...", end=' ')
    private_key = keys.get_private_key()
    print(colored("OK", 'green'))
    print(colored("[+]", 'magenta') + " Saving keys to files")
    print("Key name:")
    name = input(colored("> ", 'yellow'))
    name += '_' if name else ''
    PUBLIC_KEY_FILE = name + PUBLIC_KEY_FILE
    PRIVATE_KEY_FILE = name + PRIVATE_KEY_FILE
    print(colored("[*]", 'blue') + " Saving public key to file '"
            + colored(f"{PUBLIC_KEY_FILE}", 'white', attrs=['bold']) + "'...", end=' ')
    with open(PUBLIC_KEY_FILE, 'wb') as fh:
        fh.write(public_key)
    print(colored("OK", 'green'))
    print(colored("[*]", 'blue') + f" Saving private key to file '"
            + colored(f"{PRIVATE_KEY_FILE}", 'white', attrs=['bold']) + "'...", end=' ')
    with open(PRIVATE_KEY_FILE, 'wb') as fh:
        fh.write(private_key)
    print(colored("OK", 'green'))
    print(colored("[+]", 'magenta') + " Stop")

def encrypt(key, data, out_file):
    print(colored("[*]", 'magenta') + " Encrypting... ", end='')
    public_key = RSA.import_key(key)
    fh = open(out_file, 'wb')
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ fh.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    fh.close()
    print(colored("OK", 'green'))

def decrypt(key, passphrase, file):
    print(colored("[*]", 'magenta') + " Decrypting... ", end='')
    fh = open(file, 'rb')
    private_key = RSA.import_key(key, passphrase=passphrase)
    enc_session_key, nonce, tag, ciphertext = [ fh.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(colored("OK", 'green'))
    return data

def parse_argv(action, opts):
    bits = 2048
    passwd = None
    output_file = None
    key_file = None
    file = None

    if action == ('keygen'):
        keygen()
        return
    else:
        for o, a in opts[0]:
            if o in '-f':
                file = a
            elif o in '--key':
                key_file = a
            elif o in '-o':
                output_file = a
            elif o in '--pass':
                passwd = a
        if key_file is None:
            print(colored("[!!] No key given\n", 'red'))
            usage()
        if file is None:
            print(colored("[!!] No file given\n", 'red'))
            usage()
        key = open(key_file).read()
        if action in ('encrypt', 'enc'):
            if output_file is None:
                output_file = 'encrypted_' + file
            key = open(key_file).read()
            data = open(file, 'rb').read()
            encrypt(key, data, output_file)
            return
        elif action in ('decrypt', 'dec'):
            data = decrypt(key, passwd, file)
            if output_file is None:
                print()
                print(data.decode())
            else:
                fh = open(output_file, 'wb')
                fh.write(data)
                fh.close()
            return
        else:
            usage()


if __name__ == '__main__':
    if not len(sys.argv[1:]):
        usage()

    action = sys.argv[1]
    try:
        opts = getopt.getopt(sys.argv[2:], "o:f:", ['key=', 'pass='])
    except getopt.GetoptError as e:
        print(e)
        sys.exit(-1)

    parse_argv(action, opts)

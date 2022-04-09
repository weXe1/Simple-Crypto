# Simple-Crypto
Generating RSA key pairs, encrypting and decrypting files


```
usage:

$ python crypto.py <action> <options>

actions:

	keygen				generaiting a key pair
	encrypt <options>		encrypting a file
	decrypt <options>		decrypting a file

options:

	--key <file name>		file containing a key
	--pass <password>		password for the private key
	-f <file name>		  file to encrypt/decrypt
	-o <output file>		output file

examples:

$ python crypto.py keygen

$ python crypto.py encrypt --key TEST_public.asc -o test.bin -f test.txt

$ python crypto.py decrypt --key TEST_private.asc -f test.bin --pass 1234

```

# Overview
The code in this repo used OpenSSL's C code library.  The commands in this README.md mirror the same function as the C code but use OpenSSL's command line tool.  The C code represents my User 1 and the command line pieces represent User 2.   This is useful as it helps demo how ECDH works and validates that both sides are deriving the same key. NOTE - the HMAC operation, after the ECDH piece has completed, has been verified against https://tools.ietf.org/html/rfc4231

### Background - Diffie-Hellman
Diffie-Hellman is a Key Agreement protocol.  It is used when two parties want to derive the same shared secret over an insecure channel. The secret key cannot be observed by intercepting the communication between the two parties.  

 - Each party MUST share their own EC Public Key with the other party.
 - Each party MUST know the Named Curved being used before generating the EC Key Pair.
 - The two parties NEVER exchange the derived key.  

### Background - Diffie-Hellman alone is not enough
Diffie-Hellman provides no mechanism for ensuring that the entity on the other end of the connection is who you think it is. For mobile apps, this is where the value of other Data in Transit controls such as Certificate Pinning, HTTP Basic Auth, Access Token schemes come into play.

### Background - Why use ECDH?
Elliptic Curve Diffie-Hellman (ECDH) is an Elliptic Curve variant of the standard Diffie Hellman algorithm.  I like it over traditional DH which uses RSA for two reasons:
 - Key generation is quicker.  This is important for mobile apps when you might rotate your keys or even generate new EC Key Pairs for each session. 
 - A slightly simpler Key Derivation process.  You only need the other side's Public Key as you both have already agreed on a Named Curve [and the parameters to use in Key Generation].

### Setup OpenSSL's Command Line Tool
Print version (and All information) regarding OpenSSL install
`openssl version -a`
This will spit out your version which is likely to look like: **OpenSSL 1.0.2h  3 May 2016**
Find out where it located on your machine
`which openssl` Smoke test it works `openssl` and then type:`speed`

### Select a well known, well tested Curve
To generate a ECDH key pair (not a DH key pair), with the OpenSSL command-line tool you must first select one of the available curves. A named curve is simply a well defined and well known set of parameters that define an elliptic curve.  Print them here: `openssl ecparam -list_curves`

### User 1:  Setup is all done in C code
Generate a ECDH Key Pair in C code based on the selected Curve. Just build run the C code. It will create the required PEM files.

### Checkpoints
Ok, the OpenSSL list is very misleading.  Better read this [article] for the actual truth.  Now generate a curve PEM file: `openssl ecparam -out ec_param.pem -name prime256v1`
Check the curve was ok.
`openssl ecparam -in secp256k1.pem -text -check`
This will print something like:
`ASN1 OID: prime256v1`
`NIST CURVE: P-256`
Note - you cannot put a key file into this command.
### Checkpoint: Print out the C code
Print out the C code that was used to generate the EC Parameters.
`openssl ecparam -in ec_param.pem -text -C`
### User 2:  Setup 
Generate a ECDH Key Pair and state Explicit parameters
`openssl ecparam -in ec_paramprime256v1.pem -genkey -noout -out appKey.pem -param_enc explicit`
`openssl ecparam -in ec_paramprime256v1.pem -genkey -noout -out appKey.pem`
Now you can read the Public, Private and Named Curve by typing:
`openssl pkey -in appKey.pem -text -noout`
Now extract the public key in preparation for sharing.
`openssl pkey -in appKey.pem -pubout -out appPubKey.pem`
### Checkpoint: Check your Key Pair, Public Key
Print the newly extracted public key.
`openssl ec -in appPubKey.pem -pubin -text -noout`
Note - iIt will tell you the Private Key Length (256 bit).

A slightly abbreviated version (due to compression) is:
`openssl ec -in appPubKey.pem -pubin -text -noout -conv_form compressed`
### Checkpoint: Check your Key Pair, Private Key
Check your EC Private Key details by typing the following command.
`openssl pkey -in appKey.pem -text -noout`
Notice the Private Key elements that are excluded from the public key file.
### User 2: get Server’s Public Key
This is the tricker piece.  As it requires a login and callback. Stubbed for now.
### User 2: attempt to generate the Secret Key
The magic step.  
`openssl pkeyutl -derive -inkey appKey.pem -peerkey serPubKey.pem -out appBinaryKey.bin`
Print the binary secret key into hex.
`xxd appBinaryKey.bin`
### Checkpoint - almost there - Keys must be equal
If your keys match, you can perform the last step. The Hmac.
### Now add Authenticity to your Derived Secret
This step assumes both parties shared - out of band - a shared key that is used to create a Keyed-hash (mac).
`$ openssl dgst -sha256 -mac HMAC -macopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b appSecret.bin`
### Final test to ensure keys match
` $ cmp secret1.bin secret2.bin`
### Checkpoint : make keys readable
Convert the binary key to a b64 key
`openssl base64 -in serBinaryKey.bin -out serB64Key.txt`
You don’t need the following step but it shows the step is reversible 
`$ openssl base64 -d -in secret1.b64 -out secret3.bin`

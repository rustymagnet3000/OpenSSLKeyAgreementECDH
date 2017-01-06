# Overview
This code uses OpenSSL's C code library and OpenSSL's command line tool to demonstrate how ECDH works.

### Diffie-Hellman Background
Diffie-Hellman is a Key Agreement protocol to enure two parties can both derive the same shared secret over an insecure channel. The secret key cannot be observed by intercepting the communication between the two parties.   The two parties NEVER exchange a key they are creating a key together.

Although Diffie-Hellman key exchange provides strong protection against compromise of intercepted data, it provides no mechanism for ensuring that the entity on the other end of the connection is who you think it is. That is, this protocol is vulnerable to a man-in-the-middle attack. This is where the value of other Data in Transit controls such as Certificate Pinning come into play.

### Elliptic Curve Background
Elliptic Curve Diffie-Hellman (ECDH) is an Elliptic Curve variant of the standard Diffie Hellman algorithm.  I like it over RSA as the Key generate happens more quickly in EC due to shorter key lengths and a slightly simpler Key Derivation process (you only need the other side's Public Key as you both have already agreed on a Named Curve).

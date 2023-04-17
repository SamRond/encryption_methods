This is a simple demo file, developed to help me wrap my head around the concept of Elliptic Curve Cryptography (ECC).

There are several demos included. In the `rsa.py` file, a simple implementation of the RSA algorithm is demonstrated on UTF-8 encoded characters.

In the `ecc.py` file, a general implementation of ECC is created, and used for an instance of the `secp256k1` curve.

This curve is used in the `ecdh.py` file to demonstrate the Diffie-Hellman key exchange protocol with an Elliptic Curve.

The curve is also used in the `ecdsa.py` file to demonstrate the Digital Signature Algorithm (DSA) with an Elliptic Curve.
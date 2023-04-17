import random

from curves.ecc import secp256k1


def run_demo():
    curve = secp256k1()
    print('Curve: ', curve.name)

    # Alice
    alice_private, alice_public = curve.make_keypair()
    print("\nAlice's private key: ", hex(alice_private))
    print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public))

    # Bob
    bob_private, bob_public = curve.make_keypair()
    print("\nBob's private key: ", hex(bob_private))
    print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public))

    # Alice and Bob exchange public keys
    # Alice computes shared secret
    alice_shared = curve.scalar_multiply(alice_private, bob_public)

    # Bob computes shared secret
    bob_shared = curve.scalar_multiply(bob_private, alice_public)

    # Shared secrets are equal
    assert alice_shared == bob_shared

    print("\nShared secret: (0x{:x}, 0x{:x})".format(*alice_shared))


if __name__ == '__main__':
    run_demo()
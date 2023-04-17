import hashlib
import random

from curves.ecc import secp256k1


CURVE = secp256k1()


def sign_message(message, private_key):
    z = hash_message(message)

    r = 0
    s = 0

    while not r or not s:
        k = random.randrange(1, CURVE.order)
        x, y = CURVE.scalar_multiply(k, CURVE.g)

        r = x % CURVE.order
        s = ((z + r * private_key) * CURVE.inverse_mod(k, CURVE.order)) % CURVE.order

    return r, s


def hash_message(message):
    message_hash = hashlib.sha512(message.encode('UTF-8')).digest()
    e = int.from_bytes(message_hash, 'big')

    z = e >> (e.bit_length() - CURVE.order.bit_length())

    assert z.bit_length() <= CURVE.order.bit_length()

    return z


def verify_signature(message, signature, public_key):
    z = hash_message(message)

    r, s = signature

    w = CURVE.inverse_mod(s, CURVE.order)
    u1 = (z * w) % CURVE.order
    u2 = (r * w) % CURVE.order

    x, y = CURVE.add_point(CURVE.scalar_multiply(u1, CURVE.g), CURVE.scalar_multiply(u2, public_key))

    if (r % CURVE.order) == (x % CURVE.order):
        return 'Signature Match!'
    else:
        return 'ERROR - Signature Mismatch!'


def run_demo():
    print('Curve: ', CURVE.name)

    # Alice
    alice_private, alice_public = CURVE.make_keypair()
    print("Alice's private key: ", hex(alice_private))
    print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public))

    message = 'Hello, world!'
    signature = sign_message(message, alice_private)

    print('\nMessage: ', message)
    print("Signature: (0x{:x}, 0x{:x})".format(*signature))
    print("Verification: ", verify_signature(message, signature, alice_public))

    message = 'This is unsigned!'
    print('\nMessage: ', message)
    print("Verification: ", verify_signature(message, signature, alice_public))

    # Bob
    bob_private, bob_public = CURVE.make_keypair()

    message = 'This person doesn\'t have the right key!'
    signature = sign_message(message, alice_private)

    print('\nMessage: ', message)
    print("Signature: (0x{:x}, 0x{:x})".format(*signature))
    print("Verification: ", verify_signature(message, signature, bob_public))


if __name__ == '__main__':
    run_demo()
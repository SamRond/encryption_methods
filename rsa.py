import math


def generate_keypair(p, q):
    # p and q are prime numbers
    # returns (public, n), (private, n)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 0
    for x in range(phi - 1, 0, -1):
        if math.gcd(x, phi) == 1:
            e = x
            break

    d = 0
    for x in range(phi - 1, 0, -1):
        if (e * x) % phi == 1:
            d = x
            break

    return (e, n), (d, n)


def encrypt(message, pub):
    k, n = pub
    enc = []

    for char in message:
        enc.append((ord(char) ** k) % n)

    return enc


def decrypt(message, priv):
    k, n = priv
    unenc = ''

    for char in message:
        unenc += chr((char ** k) % n)

    return unenc


def mod_multiply(num, factor, mod):
    return (num * factor) % mod


if __name__ == '__main__':
    PRIME1 = 89
    PRIME2 = 97

    public, private = generate_keypair(PRIME1, PRIME2)

    message = 'Hello, world!'
    encrypted = encrypt(message, public)

    print(f'UNENCRYPTED: {message}')
    print(f'ENCRYPTED: {encrypted}')
    print(f'DECRYPTED: {decrypt(encrypted, private)}')

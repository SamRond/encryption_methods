import random


"""
Implementation of Elliptic Curve Cryptography (ECC) over finite fields.

Huge thanks to Andrea Corbellini for his excellent blog post on ECC:
https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
"""


def bits(n):
    while n:
        yield n & 1
        n >>= 1


class Curve:
    def __init__(self, a, b, g, order, prime=None, name="Custom"):
        self.a = a
        self.b = b
        self.g = g
        self.order = order
        self.prime = prime
        self.name = name

    def add_point(self, p, q):
        if p is None or q is None:
            return p or q

        assert self.is_on_curve(p)
        assert self.is_on_curve(q)

        px, py = p
        qx, qy = q

        if px == qx and py != qy:
            # p and q are inverse points
            return None

        m = self.slope(p, q)

        rx = m ** 2 - px - qx
        ry = -(py + m * (rx - px))

        if self.prime:
            rx = rx % self.prime
            ry = ry % self.prime

        assert self.is_on_curve((rx, ry))

        return rx, ry

    def scalar_multiply(self, n, p):
        assert self.is_on_curve(p)

        if n % self.order == 0 or p is None:
            return None

        result = None
        addend = p

        for bit in bits(n):
            if bit == 1:
                result = self.add_point(result, addend)
            addend = self.add_point(addend, addend)

        return result

    def slope(self, p, q):
        px, py = p

        if p == q:
            if self.prime:
                return (3 * (px ** 2) + self.a) * self.inverse_mod(2 * py)
            else:
                return (3 * (px ** 2) + self.a) / (2 * py)
        else:
            qx, qy = q

            if self.prime:
                m = (py - qy) * self.inverse_mod(px - qx)
            else:
                m = (py - qy) / (px - qx)

            return m

    def inverse_mod(self, k, p=None):
        # returns the inverse of k mod (prime || self.prime)
        prime = p
        if prime is None:
            prime = self.prime

        if prime is None:
            raise ValueError('Curve does not have prime modulus')

        if k == 0:
            raise ZeroDivisionError('division by zero')

        if k < 0:
            return prime - self.inverse_mod(-k, prime)

        # Extended Euclidean algorithm
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = prime, k

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        gcd, x, y = old_r, old_s, old_t

        assert gcd == 1
        assert (k * x) % prime == 1

        return x % prime

    def is_on_curve(self, p):
        x, y = p

        if self.prime:
            return (y ** 2 - (x ** 3 + self.a * x + self.b)) % self.prime == 0
        else:
            return y ** 2 == x ** 3 + self.a * x + self.b

    def negate_point(self, p):
        assert self.is_on_curve(p)

        if p is None:
            return None

        x, y = p

        if self.prime:
            result = (x, -y % self.prime)
        else:
            result = (x, -y)

        assert self.is_on_curve(result)

        return result

    def make_keypair(self):
        private_key = random.randrange(1, self.order)
        public_key = self.scalar_multiply(private_key, self.g)

        return private_key, public_key


def secp256k1():
    a = 0
    b = 7
    order = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
    prime = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
    name = 'secp256k1'

    x = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
    y = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
    g = (x, y)

    return Curve(a, b, g, order, prime, name)
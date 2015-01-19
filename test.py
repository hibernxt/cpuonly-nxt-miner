from Crypto.Util import number
import hashlib
CURVE_P = (2**255 - 19)
CURVE_A = 121665

def curve25519_monty(x1, z1, x2, z2, qmqp):
    a = (x1 + z1) * (x2 - z2) % CURVE_P
    b = (x1 - z1) * (x2 + z2) % CURVE_P
    x4 = (a + b) * (a + b) % CURVE_P

    e = (a - b) * (a - b) % CURVE_P
    z4 = e * qmqp % CURVE_P

    a = (x1 + z1) * (x1 + z1) % CURVE_P
    b = (x1 - z1) * (x1 - z1) % CURVE_P
    x3 = a * b % CURVE_P

    g = (a - b) % CURVE_P
    h = (a + CURVE_A * g) % CURVE_P
    z3 = (g * h) % CURVE_P

    return x3, z3, x4, z4

def curve25519_mult(n, q):
    nqpqx, nqpqz = q, 1
    nqx, nqz = 1, 0

    for i in range(255, -1, -1):
        if (n >> i) & 1:
            nqpqx,nqpqz,nqx,nqz = curve25519_monty(nqpqx, nqpqz, nqx, nqz, q)
        else:
            nqx,nqz,nqpqx,nqpqz = curve25519_monty(nqx, nqz, nqpqx, nqpqz, q)
    return nqx, nqz

def curve25519(secret, basepoint):
    s = secret
    s = number.bytes_to_long(s[::-1])
    basepoint = number.bytes_to_long(basepoint[::-1])

    x, z = curve25519_mult(s, basepoint)
    zmone = number.inverse(z, CURVE_P)
    z = x * zmone % CURVE_P
    return number.long_to_bytes(z)[::-1]


if __name__ == "__main__":
    for i in range(10):
        mysecret = "43DCA2233B922B2410B05F8ED03859131B10BA1B5B5C724AB120B304AA5DF22B".decode("hex")
        mypublic = "09".decode("hex")

                

        shared = curve25519(mysecret, mypublic)
        m = hashlib.sha256()
        m.update(shared)
        dig = m.hexdigest()
        first8 = dig[:8]
        second8 = dig[8:16]

        print i,shared.encode("hex"),dig


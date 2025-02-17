from ecpy.curves import Curve
from sha3 import keccak_256
from ecpy.ecdsa      import ECDSA
from ecpy.keys import ECPublicKey, ECPrivateKey


cv = Curve.get_curve('secp256k1')


message = "Hello, Ander!"
p = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
p_point = cv.generator * p
print('p_point=', p_point)

pv_key = ECPrivateKey(p, cv)
pu_key = pv_key.get_public_key()
signer = ECDSA()
signature = signer.sign(message.encode(), pv_key)
print('True signature=', int.from_bytes(signature, 'big'))



h_digest = keccak_256(message.encode()).digest()
h = int.from_bytes(h_digest, 'big')
k_digest = keccak_256(h_digest + p.to_bytes(32, 'big')).digest()
k = int.from_bytes(k_digest, 'big')
r_point = cv.generator * k
r = r_point.x
k_inv = pow(k, -1, cv.order)
s = k_inv * (h + r * p) % cv.order

print('r=', r)
print('s=', s)
print('r_point.y=', r_point.y)


#verify

h_digest = keccak_256(message.encode()).digest()
h = int.from_bytes(h_digest, 'big')
s_inv = pow(s, -1, cv.order)
r_point_prime = cv.generator * h * s_inv + p_point* r * s_inv  
print('r_point_prime=', r_point_prime)
r_prime = r_point_prime.x
print('r_prime=', r_prime)
print('r == r_prime =', r == r_prime)

# derive public key from signature

r_inv = pow(r, -1, cv.order)
p_derived = s * r_inv * r_point_prime - r_inv * h * cv.generator
print('p_derived=', p_derived)








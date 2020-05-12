#! /usr/bin/env python

from ec_utils import uber_prng
from Crypto.Cipher import AES

rng = uber_prng()

flag = "basinga_there_goes_the_backdoor"

iv  = rng.get_random(16)
key = rng.get_random(32)

aes = AES.new(key, AES.MODE_CFB, iv)

print iv.encode('hex') + aes.encrypt(flag).encode('hex')

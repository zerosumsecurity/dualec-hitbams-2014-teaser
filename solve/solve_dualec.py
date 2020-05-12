##############################################################
#
# Sage script to solve the 'random' challenge
#
##############################################################

from Crypto.Cipher import AES
import string
import time 

# elliptic curve parameters 


p = 0xfffffffdffffffffffffffffffffffffL
a = 0xd6031998d1b3bc232559cc9bbff9aee1L
b = 0x5eeefca380d0295e442c6558bb6d8a5dL
E = EllipticCurve(GF(p), [a,b])
Px = 0xe86b0b81c54bcd9b32ec5bac4c508a6eL
Py = 0x4f426faded3ca290eb0bf3c8f65e6b9bL
P = E(Px,Py)
Qx = 0x6eb63b8498d108459ea891cbcb8319e4L
Qy = 0x2d19b5f118bbb6978fc24cc56ef8085bL
Q = E(Qx,Qy)
Rx = 0x4ca91fe907c82a68a7cf562a2b55d436L
Ry = 0xf86a643915962ae0bbbb77b9f4a9be80L
R = E(Rx,Ry)


data = "b9597a059f4ae5a10c3e79c2743ca280644eb7b032d162251a84cdbc1a7e78592d900e7e3b6e1364a722093935a44d"
       
# parse the data from the encrypted blob
enc_flag = data[32:].decode('hex')
x = int(data[:32], 16) # the x-coordinate contained in the iv 
iv = data[:32].decode('hex')

SMALL_ORDER = R.order() # the order of the point R on the elliptic curve
q = E.cardinality() # the number of points on the elliptic curve

t0 = time.time() # start the timer

# recover the secret component modulo a prime factor of the group order via pollard rho
def solve_local(factor):
	cofac = int(q/factor)
	# lift P and Q to the subgroup of order 'factor'
	Pt = cofac*P
	Qt = cofac*Q
	# solve the discrete log problem in the small subgroup
	dl = discrete_log_rho(Pt ,Qt, ord = factor, operation = '+')
	print "[*] recovered discrete log modulo", factor
	return dl

# find k such that P = k*Q on the elliptic curve
def recover_secret_exponent(flag):
	if flag:
		# as precomputed 
		return 265932790776829999322959240429346273803
	else:
		# redo the computation of the discrte log of P to the base Q 
		print "[*] start discrete log calculations"
		F = q.factor()
		print "[*] group order factored as" , F
		factors = [f[0] for f in F]
		local_solves = [ solve_local(factor) for factor in factors ]
		return CRT_list(local_solves, factors) # glue the local results together to get the secret exponent
	  

# a valid flag stands out by being a printable string
def check_flag(flag):
	if not all(c in string.printable for c in flag): 
		return False
	else:
		return True

# convert a Sage integer to the raw hex representation
def num_to_raw_hex(num):
	rnd = '%032x' % int(num)
	return rnd.decode('hex')

# complete a point from it's x-coordinate
def get_y_coordinate(x):
	x = int(x)
	y = mod(pow(x,3) + a*x +b, p)
	if y.is_square():
		return int(y.sqrt())
	else:
		return 0

# loop over the unknown contributions of r*R; we will need to guess three values
# of r in sequential steps of the prng - each value of r is needed only module the order or R of course
def find_flag(s0P):
	for r0 in range(SMALL_ORDER):	
		t1 = r0*R 
		s1 = (t1 + s0P).xy()[0] # update state
		s1 = int(s1)
		rnd = (s1*Q).xy()[0]
		key0 = num_to_raw_hex(rnd)
		for r1 in range(SMALL_ORDER):
						
			t1 = r1*R 
			t2 = s1*P
			s2 = (t1 + t2).xy()[0] # update state
			s2 = int(s2)
			
			rnd = (s2*Q).xy()[0]
			key = key0 + num_to_raw_hex(rnd)
			key = key[:32]
			
			aes = AES.new(key, AES.MODE_CFB, iv) # init aes object
			flag = aes.decrypt(enc_flag) # decrypt the flag
	
			if check_flag(flag):# test the candidate flag
				print "[*] flag found at:", r0, r1
				print "[*] flag found:", flag
				t = time.time()
				print "[*] time elapsed so far:", parse_time(t-t0)
				# flag as in random_v2 is at (r0, r1, r2) = (70,72,30)
				return True
	return False

# print timing info
def parse_time(gap):
	s= int(gap%60)
	t= int((gap-s)/60)
	m= int(t%60)
	h= int((t-m)/60)
	return "{0:d}h {1:d}m {2:d}s".format(h,m,s) 

# decrypt the flag
def solve():
	# set flag to True to skip over the re-computatuon of the discrete log
	secret_exp = recover_secret_exponent(True)
	print "[*] backdoor exponent recovered:", secret_exp
	t = time.time()
	print "[*] time elapsed so far:", parse_time(t-t0)

	# with help of the backdoor discrete log, compute the two possible intermediate states of the prng	
	y = get_y_coordinate(x)
	
	if 0 == y:
		print "Error"
		return
	
	Start1 = secret_exp*E(x,y)
	Start2 = secret_exp*E(x,p-y)
	
	print "[*] state after iv generation recovered"
	t = time.time()
	print "[*] time elapsed so far:", parse_time(t-t0)

	if Start1 is not None:
		if find_flag(Start1):
			return
	if Start2 is not None:
		if find_flag(Start2):
			return
		
	print "[*] flag not found"
	
solve()
	

#! /usr/bin/env python

#######################################################################
# 
# credits to Lis - code partly taken from
# https://bitcointalk.org/index.php?topic=23241.0
#
#######################################################################

class CurveFp( object ):
	def __init__( self, p, a, b ):
    		self.__p = p
   		self.__a = a
    		self.__b = b

  	def p( self ):
    		return self.__p

  	def a( self ):
    		return self.__a

  	def b( self ):
    		return self.__b

  	def contains_point( self, x, y ):
    		return ( y * y - ( x * x * x + self.__a * x + self.__b ) ) % self.__p == 0

class Point( object ):
  	def __init__( self, curve, x, y, order = None ):
    		self.__curve = curve
    		self.__x = x
    		self.__y = y
    		self.__order = order
    		if self.__curve: assert self.__curve.contains_point( x, y )
    		if order: assert self * order == INFINITY
 
  	def __add__( self, other ):
    		if other == INFINITY: return self
    		if self == INFINITY: return other
    		assert self.__curve == other.__curve
    		if self.__x == other.__x:
      			if ( self.__y + other.__y ) % self.__curve.p() == 0:
        			return INFINITY
      			else:
        			return self.double()

    		p = self.__curve.p()
    		l = ( ( other.__y - self.__y ) * \
          	inverse_mod( other.__x - self.__x, p ) ) % p
    		x3 = ( l * l - self.__x - other.__x ) % p
    		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
    		return Point( self.__curve, x3, y3 )

  	def __mul__( self, other ):
    		def leftmost_bit( x ):
      			assert x > 0
      			result = 1L
      			while result <= x: result = 2 * result
      			return result / 2

    		e = other
    		if self.__order: e = e % self.__order
    		if e == 0: return INFINITY
    		if self == INFINITY: return INFINITY
    		assert e > 0
    		e3 = 3 * e
    		negative_self = Point( self.__curve, self.__x, -self.__y, self.__order )
    		i = leftmost_bit( e3 ) / 2
    		result = self
    		while i > 1:
      			result = result.double()
      			if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + self
      			if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
      			i = i / 2
    		return result

  	def __rmul__( self, other ):
    		return self * other

  	def __str__( self ):
    		if self == INFINITY: return "infinity"
    		return "(%d,%d)" % ( self.__x, self.__y )

  	def double( self ):
    		if self == INFINITY:
      			return INFINITY

    		p = self.__curve.p()
    		a = self.__curve.a()
    		l = ( ( 3 * self.__x * self.__x + a ) * \
          		inverse_mod( 2 * self.__y, p ) ) % p
    		x3 = ( l * l - 2 * self.__x ) % p
    		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
    		return Point( self.__curve, x3, y3 )

  	def x( self ):
    		return self.__x

  	def y( self ):
    		return self.__y

  	def curve( self ):
    		return self.__curve
  
  	def order( self ):
    		return self.__order
    
def inverse_mod( a, m ):
  	if a < 0 or m <= a: a = a % m
  	c, d = a, m
  	uc, vc, ud, vd = 1, 0, 0, 1
  	while c != 0:
    		q, c, d = divmod( d, c ) + ( c, )
    		uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
  	assert d == 1
  	if ud > 0: return ud
  	else: return ud + m


INFINITY = Point( None, None, None )

#######################################################################
#
# see secp128r2 as defined in paragraph 2.3.3 of 
# http://www.secg.org/download/aid-386/sec2_final.pdf
#
#######################################################################

p = 0xfffffffdffffffffffffffffffffffffL
a = 0xd6031998d1b3bc232559cc9bbff9aee1L
b = 0x5eeefca380d0295e442c6558bb6d8a5dL
E = CurveFp( p, a, b )

#######################################################################
#
# random ponts on the elliptic curves, generated verifiably at random
#
#######################################################################

Rx = 0x4ca91fe907c82a68a7cf562a2b55d436L
Ry = 0xf86a643915962ae0bbbb77b9f4a9be80L
R = Point(E, Rx,Ry)
# md5(xR) = e86b0b81c54bcd9b32ec5bac4c508a6e = xP
Px = 0xe86b0b81c54bcd9b32ec5bac4c508a6eL
Py = 0x4f426faded3ca290eb0bf3c8f65e6b9bL
P = Point(E, Px,Py)
# md5(xP) = 6eb63b8498d108459ea891cbcb8319e4 = xQ
Qx = 0x6eb63b8498d108459ea891cbcb8319e4L
Qy = 0x2d19b5f118bbb6978fc24cc56ef8085bL
Q = Point(E, Qx,Qy)

#######################################################################
#
# our super duper provably number theoretically secure uber prng 
#
#######################################################################

class uber_prng( object ):
  	def __init__( self ): 
		# start from a fresh seed
		self.__state = open("/dev/urandom","rb").read(16) 
		self.__state = int(self.__state.encode('hex'), 16)
	
	def step( self ):
		# pfs random extraction
		rnd = ((self.__state)*Q).x() 
		# add 16 bytes of extra entropy
		r = open("/dev/urandom","rb").read(16) 
		r = int(r.encode('hex'), 16) 
		t1 = r*R 
		t2 = (self.__state)*P
		# update state
		self.__state = (t1 + t2).x() 
		res = '%032x' % rnd
		return res.decode('hex')

	def get_random( self, num_bytes ):
		rnd = ""
		while len(rnd) < num_bytes:
			rnd += self.step()
		return rnd[:num_bytes]
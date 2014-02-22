#
# Dan Clark
#
# Utilities provided by the course for Udacity Applied Cryptography Unit 4
#

from string import printable

############################
# This eliminates the recursion in the mod_exp
# shown in lecture
# and does bitwise operations
# to speed things up a bit
# but the number of multiplications stays
# the same
def mod_exp(a, b, q):
    """return a**b % q"""
    val = 1
    mult = a
    while b > 0:
        odd = b & 1 # bitwise and
        if odd == 1:
            val = (val * mult) % q
            b -= 1
        if b == 0:
            break
        mult = (mult * mult) % q
        b = b >> 1 # bitwise divide by 2
    return val
    
    # Below are the typical bit manipulation functions
# that you might find useful
# Note that ASCII_BITS is set to 7 for this problem

BITS = ('0', '1')
ASCII_BITS = 8 

def display_bits(b):
    """converts list of {0, 1}* to string"""
    return ''.join([BITS[e] for e in b])

def seq_to_bits(seq):
    return [0 if b == '0' else 1 for b in seq]

def pad_bits(bits, pad):
    """pads seq with leading 0s up to length pad"""
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits
        
def convert_to_bits(n):
    """converts an integer `n` to bit array"""
    result = []
    if n == 0:
        return [0]
    while n > 0:
        result = [(n % 2)] + result
        n = n // 2
    return result

def string_to_bits(s):
    def chr_to_bit(c):
        assert type(c) == int or type(c) == str
        c_asInt = ord(c) if type(c) == str else c
        return pad_bits(convert_to_bits(c_asInt), ASCII_BITS)
    return [b for group in 
            map(chr_to_bit, s)
            for b in group]

def bits_to_char(b):
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)

def list_to_string(p):
    return ''.join(p)

def bits_to_string(b):
    return ''.join([bits_to_char(b[i:i + ASCII_BITS]) 
                    for i in range(0, len(b), ASCII_BITS)])

def bits_to_int(b):
    """
    Returns the integer represented by the list of bits b.
    """
    total = 0
    for i in range(len(b)):
        assert b[-i] == 0 or b[-i] == 1
        total += b[-(i + 1)] * (2 ** i)
    
    return total

# is_valid returns True if the input consist of valid
# characters (numbers, upper case A-Z and lower case a-z and space)
# The message still might be garbage, but this is a decent
# and reasonably fast preliminary filter
# valid_chars = set(c for c in string.printable[:62])
valid_chars = set(c for c in printable)
valid_chars.add(' ')
def is_valid_message(decode_guess):
    return all(d in valid_chars for d in decode_guess)


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
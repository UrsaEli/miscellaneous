##
#
# Dan Clark
# thedanclark@gmail.com
# 17 January 2014
# Udacity - Applied Cryptography
# HW2-5 Version 2
# Finding hash collisions for hash computed with counter mode
#
# In this assignment your job is to write a function, find_collision,
# that finds a hash collision for any given input message.
#
# The input message will be at least four blocks (64 characters) long.
#
# My implementation creates a hash collision by simply swapping the first two
# blocks of the message.  Since the hash is computed by XORing the results of all
# the counter-encrypted blocks, the end result will still be the same due to the
# commutativity of the XOR operation.
#

from Crypto.Cipher import AES
from copy import copy

# Remember, this is NOT secure cryptology code
# This is for fun and education.  Do not use this
# to protect the classified files from Area 51

def find_collision(message):
    new_message = copy(message)
    ####################
    # START YOUR CODE HERE
    block_size = hash_inputs()[0]
    assert len(message) >= block_size * 2, \
            "Can't swap first two blocks of the message if we don't have that many bits"
    
    # Swap the first two blocks.  Since we're just XORing all the encrypted blocks
    # to get the hash, the resulting hash should be the same after this swap.
    new_message[0 : block_size], new_message[block_size : block_size * 2] = \
            new_message[block_size : block_size * 2], new_message[0:block_size]

    assert get_block(new_message, 0, block_size) == message[block_size : block_size * 2]

    return new_message
    # END OF YOUR CODE
    ####################

def test():     
    messages = ["Trust, but verify. -a signature phrase of President Ronald Reagan",
                "The best way to find out if you can trust somebody is to trust them. (Ernest Hemingway)",
                "If you reveal your secrets to the wind, you should not blame the wind for revealing them to the trees. (Khalil Gibran)",
                "I am not very good at keeping secrets at all! If you want your secret kept do not tell me! (Miley Cyrus)",
                "This message is exactly sixty four characters long and no longer"]
    for m in messages:
        m = string_to_bits(m)
        new_message = find_collision(m)
        if not check(m, new_message):
            print("Failed to find a collision for '{0}'".format(m))
            return False
    return True

from Crypto.Cipher import AES

#################
# Below are some functions
# that you might find useful
    
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
        return pad_bits(convert_to_bits(ord(c)), ASCII_BITS)
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

def pad_bits_append(small, size):
    # as mentioned in lecture, simply padding with
    # zeros is not a robust way way of padding
    # as there is no way of knowing the actual length
    # of the file, but this is good enough
    # for the purpose of this exercise
    diff = max(0, size - len(small))
    return small + [0] * diff

def xor_bits(bits_a, bits_b):
    """returns a new bit array that is the xor of `bits_a` and `bits_b`"""
    return [a^b for a, b in zip(bits_a, bits_b)]

def bits_inc(bits):
    """modifies `bits` array in place to increment by one
    
    wraps back to zero if `bits` is at its maximum value (each bit is 1)
    """
    # start at the least significant bit and work towards
    # the most significant bit
    for i in range(len(bits) - 1, -1, -1):
        if bits[i] == 0:
            bits[i] = 1
            break
        else:
            bits[i] = 0

def aes_encoder(block, key):
    block = pad_bits_append(block, len(key))
    # the pycrypto library expects the key and block in 8 bit ascii 
    # encoded strings so we have to convert from the bit array
    block = bits_to_string(block)
    key = bits_to_string(key)
    ecb = AES.new(key.encode("latin-1"), AES.MODE_ECB)
    return string_to_bits(str(ecb.encrypt(block.encode("latin-1")), encoding="latin-1"))

def get_block(plaintext, i, block_size):
    """returns the ith block of `plaintext`"""
    start = i * block_size
    if start >= len(plaintext):
        return None
    end = min(len(plaintext), (i+1) * block_size)
    return pad_bits_append(plaintext[start:end], block_size)

def get_blocks(plaintext, block_size):
    """iterates through the blocks of blocksize"""
    i = 0
    while True:
        start = i * block_size
        if start >= len(plaintext):
            break
        end = (i+1) * block_size
        i += 1
        yield pad_bits_append(plaintext[start:end], block_size)

def _counter_mode_inner(plaintext, key, ctr, block_enc):
    eblock = block_enc(ctr, key)
    cblock = xor_bits(eblock, plaintext)
    bits_inc(ctr)
    return cblock

def counter_mode(plaintext, key, ctr, block_size, block_enc):
    """Return the counter mode encoding of `plaintext"""
    cipher = []
    # break the plaintext into blocks
    # and encode each one
    for block in get_blocks(plaintext, block_size):
        cblock = _counter_mode_inner(block, key, ctr, block_enc)
        cipher.extend(cblock)
    return cipher

def counter_mode_hash(plaintext):
    block_size, block_enc, key, ctr = hash_inputs()
    hash_ = None
    for block in get_blocks(plaintext, block_size):
        cblock = _counter_mode_inner(block, key, ctr, block_enc)
        if hash_ is None:
            hash_ = cblock
        else:
            hash_ = xor_bits(hash_, cblock)
    return hash_

def hash_inputs():
    block_size = 128
    block_enc = aes_encoder
    key = string_to_bits("Vs7mHNk8e39%CXeY")
    ctr = [0] * block_size
    return block_size, block_enc, key, ctr

def _is_same(bits_a, bits_b):
    if len(bits_a) != len(bits_b):
        return False
    for a, b in zip(bits_a, bits_b):
        if a != b:
            return False
    return True

def check(message_a, message_b):
    """return True if `message_a` and `message_b` are
    different but hash to the same value"""

    if _is_same(message_a, message_b):
        return False
    
    hash_a = counter_mode_hash(message_a)
    hash_b = counter_mode_hash(message_b)

    return _is_same(hash_a, hash_b)

if __name__ == "__main__":
    test()
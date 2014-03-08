#
# Dan Clark
# https://github.com/dandclark
#
# Udacity Applied Cryptography
# HW 5 - Challenge Problem
#
# Implements the BEAST attack on SSL.
#
# Original problem description:
#
# For this problem, we've attempted to make a
# simplified example demonstrating the beast
# attack.  We've created a simple site
# that has a secret message, `m`.

# You have the ability to send a message, attack, to 
# the server.  The server will prepend
# `attack` to `m` and then encrypt the resulting
# message using CBC mode with a block size
# of 128 bits.  

# The initialization vector, iv, is used from
# the the last block of the last encryption.
# Dave outlined how to deal with and use 
# this in lecture.  He also discussed a paper
# by Thai Duong and Juliano Rizzo that might
# have more useful information

# Specifically, the code below POSTs two values
# `attack` and `token`.  `attack` is the string
# prepended to the message and `token` is used
# internally to maintain a session and keep track
# of the last `iv.`  We highly recommend you don't
# mess with it.
# If `token` is empty or invalid - the server generates a
# random iv value and uses that for the encryption

# Rarely, similar to how a user might close and start
# a new TLS session, the server will start over, pick a new random
# IV and use that for encryption.

# The send function takes in a string as an argument and returns
# a string as an argument.  This is different from previous
# assignments where most functions took in arrays of bits.
# Just remember that each character represents a byte (8 bits)

# More information available: http://forums.udacity.com/cs387-april2012/questions/3506/hw5-5-challenge-question-discussion

import functools
import urllib.parse
import urllib.request
import json
import base64

BLOCK_SIZE = 128
site = "http://cs387.udacity-extras.appspot.com/beast"

CHARACTERS_PER_BLOCK = 16
ENCODING = 'latin-1'

def unencode_json(txt):
    txt = txt.decode(ENCODING)
    d = json.loads(txt)
    return dict((k,
                 base64.urlsafe_b64decode(v))
                for k,v in d.items())

def _send(attack=None, token=None):
    data = {}

    if attack is not None:
        data["attack"] = base64.urlsafe_b64encode(attack)
    if token is not None:
        data["token"] = base64.urlsafe_b64encode(token)
        
    # here we make a post request to the server, sending
    # the attack and token data
    response = urllib.request.urlopen(site, urllib.parse.urlencode(data).encode(ENCODING))
    json = response.read()
    json = unencode_json(json)
    return json
    
_TOKEN = None
def send(attack=None):
    """send takes a string (representing bytes) as an argument 
    and returns a string (also, representing bytes)"""
    global _TOKEN
    json = _send(attack, _TOKEN)
    _TOKEN = json["token"]
    return json["message"]

def xor(bytes1, bytes2, *additional_bytes):
    return bytes([functools.reduce(lambda a, b: a ^ b, byte) for byte in zip(bytes1, bytes2, *additional_bytes)])

def check_guess(message_start, guess_character):
    """
    Returns True if guess_character is the next byte in the message
    after the array of bytes specified in message_start.
    """
    
    # Prepend the amount of characters required to cause the character
    # we are guessing to be the last character in its block.
    if (len(message_start) // CHARACTERS_PER_BLOCK) < 2:
        start_prepended_data = b"x" * (CHARACTERS_PER_BLOCK * 2 - \
            len(message_start) - 1)
    else:
        start_prepended_data = b"x" * (CHARACTERS_PER_BLOCK - \
                (len(message_start) % CHARACTERS_PER_BLOCK) - 1)
    
    print("Sending initial attack", start_prepended_data , "with length", len(start_prepended_data ))
    received = send(start_prepended_data )

    encrypted_message_block_index = max(1, len(message_start) // CHARACTERS_PER_BLOCK)
    encrypted_message_block = received[encrypted_message_block_index * CHARACTERS_PER_BLOCK:(encrypted_message_block_index + 1) * CHARACTERS_PER_BLOCK]
    message_block_iv = received[(encrypted_message_block_index - 1) * CHARACTERS_PER_BLOCK:encrypted_message_block_index * CHARACTERS_PER_BLOCK]

    assert len(encrypted_message_block) == CHARACTERS_PER_BLOCK
    assert len(message_block_iv) == CHARACTERS_PER_BLOCK
    
    # The IV used for the next message is the last block from the first message
    # (this is the key weakness that enables the attack).
    guess_block_iv = received[-CHARACTERS_PER_BLOCK:]
    
    # Set up the block that, if guess_character is correct, will match
    # the last plaintext block of the encrypted message.
    if len(message_start) < CHARACTERS_PER_BLOCK:
        guess_message_block = (b"x" * (CHARACTERS_PER_BLOCK - \
                len(message_start) - 1)) \
                + message_start + bytearray([guess_character])
    else:
        guess_message_block = message_start[-(CHARACTERS_PER_BLOCK - 1):] + bytearray([guess_character])
    
    print("guess_message_block:", guess_message_block, "length", len(guess_message_block))
    
    # Set things up so that the second block in the next message will
    # encrypt to the same value as encrypted_message_block if guess_message_block
    # does in fact match the actual value of the last block of the
    # encrypted message.
    guess_prepended_data = xor(guess_message_block, guess_block_iv, message_block_iv)
    
    next_message = send(guess_prepended_data)

    encrypted_guess_block = next_message[0:CHARACTERS_PER_BLOCK]
    print("encrypted_guess_block:", encrypted_guess_block,
            "length", len(encrypted_guess_block))
    return encrypted_guess_block == encrypted_message_block
    
if __name__ == "__main__":
    print("Starting attack...")
    message = bytearray()
    # I'm not bothering to write in a termination condition for now;
    # it's straightforward enough just to let it spin and stop things
    # manually once the full text of the message has been obtained.
    while True:
        for i in range(2 ** 8):
            print("Guessing", i)
            if check_guess(message, i):
                message.append(i)
                print("Guess of", i, "is correct, message so far:", message)
                break


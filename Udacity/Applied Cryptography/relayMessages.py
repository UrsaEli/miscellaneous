#
# Dan Clark
# https://github.com/dandclark
#
# Udacity Applied Cryptography
# Final Exam Challenge Question
#
# Original problem description:
#
# For this problem, Alice and Bob want to communicate
# They have set up two servers to respond to messages
# and you need to transfer the messages between the two.
#
# The protocol goes as follows:
# 1) a. Establish a session with Alice
#    b. Establish a session with Bob
# 2) a. Send Alice's public information to Bob
#    b. Send Bob's public information to Alice
# 3) Relay messages
#
# Step 1 - Establishing a session
# The function `initialize` can be used to establish a session.
# Alice responds to a POST request with the `type` key set to "init".
# She will send back two values: a token which is used to track the 
# session and a public value, g^x.  The token will expire after 20 minutes,
# so you will need to re-initialize a session after that time
#
# Step 2 - Exchanging public information
# Alice now needs Bob's public value.  The function `send_key` can be
# used to send this.  The function makes a POST request.  Alice responds with 
# a successful status.
#
# Step 3 - Relay messages
# Now that Alice and Bob have a shared secret key, they can use that
# to encrypt secret messages.  You will need to relay these messages.
# Use the `recieve_msg` function to get the first message to send from Alice
# Then, take the values recieved from that and send them to Bob, who will
# respond.  Take his response and send it back to Alice.  Repeat.
#
# Errors
# If you try to do something that Alice and Bob don't like, for example sending a message
# without first exchanging public information, they will respond with 
# a 501 status code and more information in the response.
#
# As with the challenge problem of Unit 5, this assignment requires that
# you run code on your own environment.  It will not work if you write
# code in the Udacity IDE and hit RUN or SUBMIT.
#
# You're allowed to use whatever programming language you want.  The 
# code provide below can be used as a reference implementation.
#

import urllib.parse
import urllib.request

import json

from Crypto.Cipher import AES
from hashlib import sha1
from unit4_util import bits_to_int, string_to_bits, hex_string_to_bits, bits_to_string, \
        convert_to_bits, pad_to_block, pad_bits, pad_bits_append, xor, ASCII_BITS, is_valid_message

ENCODING = 'latin-1'
AES_KEY_BITS = 128
AES_BLOCK_BITS = 128
AES_CTR_NONCE_BITS = 32
AES_CTR_IV_BITS = 64
AES_CTR_COUNT_BITS = 32

# Using zero for the private key means that the shared "secret" will always
# just be 1, so we can use it with both parties.
X_EVE = 0

SAMPLE_LFSR_OUTPUT = [0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0]
A51_LFSR_0_LENGTH = 19
A51_LFSR_0_TAPPED_BITS = [13,16,17,18]
A51_LFSR_1_LENGTH = 22
A51_LFSR_1_TAPPED_BITS = [20,21]
A51_LFSR_2_LENGTH = 23
A51_LFSR_2_TAPPED_BITS = [7,20,21,22]

BOB_CIPHERTEXT = "8d801f00c7554d3980b0c4f400c1ebc572d86f57f48d322b8e7c3a1f01c531dbe772b77be5acd34bf1979b70089615ace253c4b01350f36f82215f164b7934fdd48a30"
BOB_PLAINTEXT = "An important question: What do you get if you multiply six by nine?"

LFSR_DECRYPTION_ATTEMPTS = 100000

base = "http://cs387.udacity-extras.appspot.com/final"
Alice = (base + "/alice", "alice")
Bob = (base + "/bob", "bob")
Alex = (base + "/alex", "alex")
Betty = (base + "/betty", "betty")

def aes_encode(block, key):
    block = pad_bits_append(block, len(key))
    # the pycrypto library expects the key and block in 8 bit ascii 
    # encoded strings so we have to convert from the bit array
    block = bits_to_string(block)
    key = bits_to_string(key)
    ecb = AES.new(key.encode("latin-1"), AES.MODE_ECB)
    return string_to_bits(str(ecb.encrypt(block.encode("latin-1")), encoding="latin-1"))

def check_output(output):
    data = output.read()
    if output.getcode() != 200:
        raise Exception(data)
    data = json.loads(data.decode(ENCODING))
    return data

def get_pg():
    output = urllib.request.urlopen(base)
    data = check_output(output)
    # returns {"p":<large prime>, "g":<generator for p>}
    return data

def initialize(person):
    data = {'type':'init'}
    output = urllib.request.urlopen(person, urllib.parse.urlencode(data).encode(ENCODING))
    data = check_output(output)
    # returns a dictionary 
    # {"token":<token_value>, "public": <g^x>}
    return data

def send_key(person, token, public, name):
    """
    person: url of Alice/Bob
    token: token used to track session
    public: the public value of the other party
    name: the name of the other party - "alice", "bob"
    """
    data = {'type':'key',
            'token':token,
            'public':public,
            'name':name}
    output = urllib.request.urlopen(person, urllib.parse.urlencode(data).encode(ENCODING))
    data = check_output(output)
    # Should be a response {"status":"success"}
    return data

def receive_msg(person, token):
    data = {'type':'msg',
            'token':token}
    output = urllib.request.urlopen(person, urllib.parse.urlencode(data).encode(ENCODING))
    data = check_output(output)
    # should be a response
    # {"msg":<cipher>, "iv":<initialization vector>}
    return data

def send_msg(person, token, cipher, iv):
    data = {'type':'msg',
            'token':token,
            'message':cipher,
            'iv':iv}
    output = urllib.request.urlopen(person, urllib.parse.urlencode(data).encode(ENCODING))
    data = check_output(output)
    # If the person doesn't have
    # a response to the message, the response will
    # just be {"status":"success"}
    # else, the response will be {"status":"sucess", 
    #                             "reply":{"msg":<cipher>,
    #                                      "iv":<initialization vector>}}
    return data


class ShiftRegister:
    """
    Implementation of a Linear Feedback Shift Register
    """
    
    def __init__(self, initial_state, tapped_bits):
        """
        initial_state is an array of boolenas giving the starting state
        of the LFSR (and, implicitly, its length).
        tapped_bits is an array of indices into the register state array
        that indicates which bits are XORed to obtain the next input to
        the LFSR.
        """
        self.state = initial_state
        self.tapped_bits = tapped_bits
        
    def get_next_output(self):
        """
        Returns the next output bit of the LFSR and clocks
        the LFSR by one step.
        """
        output = self.state[-1]
        tapped_bit_values = [self.state[i] for i in self.tapped_bits]
        num_true_tapped_bits = sum(1 for bit in tapped_bit_values if bit)
        self.state = [num_true_tapped_bits % 2] + self.state[:-1]
        return output
        
    def get_output_bits(self, number_of_bits):
        """
        Returns an array containing the next number_of_bits bits of
        output from the LFSR (with the first at index 0, second at
        index 1, etc...
        """
        return [self.get_next_output() for i in range(number_of_bits)]
    
    
def get_ctr_info(private_value, received_public_value):
    """
    Calculates shared secret and returns (key, nonce) for use with AES-CTR
    Expects parameters to be ints.  Returns key and nonce as hex strings.
    """
    pg = get_pg()
    p = int(pg['p'], 16)    

    shared_secret = pow(received_public_value, private_value, p)
    shared_secret_bits = pad_to_block(convert_to_bits(shared_secret), ASCII_BITS)
    shared_secret_bytestring = bits_to_string(shared_secret_bits).encode(encoding='latin-1')
    shared_secret_hash = sha1(shared_secret_bytestring).hexdigest()
    assert len(shared_secret_hash) == 40
    
    # sha1 generates hash of 20 bytes.  Use first 16 bytes for the key and last 4 for the nonce
    key = shared_secret_hash[0:32]
    nonce = shared_secret_hash[32:40]
    return (key, nonce)
    
    
def run_mitm_session(first, second):
    """
    Run a message exchange between the specified parties, but
    perform a MITM attack using a known private key for the
    exchange with each in order to snoop on the contents
    of the messages.
    """
    first_initialization_response = initialize(first[0])
    first_session_token = first_initialization_response['token']
    
    second_initialization_response = initialize(second[0])
    second_session_token = second_initialization_response['token']
    
    pg = get_pg()
    p = int(pg['p'], 16)
    g = int(pg['g'], 16)
    
    eve_key_response_int = pow(g, X_EVE, p)
    eve_key_response = hex(eve_key_response_int)[2:] # chop off the "0x"
    
    first_key_received_response = send_key(first[0], first_session_token,
            eve_key_response, second[1])
    second_key_received_response = send_key(second[0], second_session_token,
            eve_key_response, first[1])
    
    (first_ctr_key, first_ctr_nonce) = get_ctr_info(X_EVE, int(first_initialization_response['public'], 16))
    (second_ctr_key, second_ctr_nonce) = get_ctr_info(X_EVE, int(second_initialization_response['public'], 16))
    
    first_person_message = receive_msg(first[0], first_session_token)
    
    first_person_decrypted_message = counter_mode_encrypt(first_person_message['msg'], first_ctr_key, first_person_message['iv'], first_ctr_nonce)
    first_person_decrypted_message_str = bits_to_string(first_person_decrypted_message)
    first_person_decrypted_message_hex = hex(bits_to_int(first_person_decrypted_message))[2:]

    test_encrypted_message_bits = counter_mode_encrypt(first_person_decrypted_message_hex, first_ctr_key, first_person_message['iv'], first_ctr_nonce)
    test_encrypted_message_str = hex(bits_to_int(test_encrypted_message_bits))[2:]
    assert test_encrypted_message_str == first_person_message['msg']    

    # Set up the message to be sent through the MITM session with second person
    first_re_encrypted_message_bits = counter_mode_encrypt(first_person_decrypted_message_hex, second_ctr_key, first_person_message['iv'], second_ctr_nonce)
    first_re_encrypted_message_str = hex(bits_to_int(first_re_encrypted_message_bits))[2:]
    
    response = send_msg(second[0], second_session_token,
            first_person_message['msg'], first_person_message['iv'])
    
    recipient, sender = first, second
    recipient_session_token, sender_session_token = first_session_token, second_session_token
    recipient_ctr_key, sender_ctr_key = first_ctr_key, second_ctr_key
    recipient_ctr_nonce, sender_ctr_nonce = first_ctr_nonce, second_ctr_nonce
    
    while 'reply' in response and 'iv' in response['reply'] and len(response['reply']['iv']) > 0:    

        decrypted_response = counter_mode_encrypt(response['reply']['msg'],
                sender_ctr_key, response['reply']['iv'], sender_ctr_nonce)
        decrypted_response_str = bits_to_string(decrypted_response)
        print(sender[1], "decrypted_response_str", decrypted_response_str)
    
        response = send_msg(recipient[0], recipient_session_token,
                response['reply']['msg'], response['reply']['iv'])
        
        # Switch places
        recipient, sender = sender, recipient
        recipient_session_token, sender_session_token = sender_session_token, recipient_session_token
        recipient_ctr_key, sender_ctr_key = sender_ctr_key, recipient_ctr_key
        recipient_ctr_nonce, sender_ctr_nonce = sender_ctr_nonce, recipient_ctr_nonce
        

def run_exchanges():

    pg = get_pg()
    
    # Alex and Betty exchange
    #run_mitm_session(Alex, Betty)
    #run_mitm_session(Alice, Bob)
    #run_mitm_session(Betty, Bob)
    #run_mitm_session(Alex, Bob)
    run_mitm_session(Alice, Alex)
    #run_mitm_session(Alice, Betty)
    
def counter_mode_encrypt(plaintext, key, iv, nonce):
    """
    Encrypts the specified plaintext key using AES-CTR.  Returns the ciphertext
    as an array of bits
    """
    plaintext_bits = hex_string_to_bits(plaintext)
    nonce_bits = pad_bits(hex_string_to_bits(nonce), AES_CTR_NONCE_BITS)
    key_bits = pad_bits(hex_string_to_bits(key), AES_KEY_BITS)
    iv_bits = pad_bits(hex_string_to_bits(iv), AES_CTR_IV_BITS)
    
    assert AES_CTR_NONCE_BITS + AES_CTR_IV_BITS + AES_CTR_COUNT_BITS == AES_BLOCK_BITS

    count_value = 1
    encrypted_bits = []

    while count_value <= ((len(plaintext_bits) - 1) // AES_BLOCK_BITS) + 1:
    
        count_bits = pad_bits(convert_to_bits(count_value), AES_CTR_COUNT_BITS)
    
        ctr_block = nonce_bits + iv_bits + count_bits
        
        keystream_block = aes_encode(ctr_block, key_bits)

        plaintext_block = plaintext_bits[(count_value - 1) * AES_BLOCK_BITS:count_value * AES_BLOCK_BITS]
        
        bits_to_pad = AES_BLOCK_BITS - len(plaintext_block)
        assert bits_to_pad % ASCII_BITS == 0

        keystream_block = keystream_block[:len(plaintext_block)]
        
        encrypted_block = xor(plaintext_block, keystream_block)
        
        encrypted_bits += encrypted_block
        
        # print("nonce_bits", nonce_bits)
        # print("key_bits", key_bits)
        # print("iv_bits", iv_bits)
        # print("ctr_block", ctr_block)
        # print("keystream_block", keystream_block)
        # print("encrypted_block", encrypted_block)
        
        count_value += 1
    
    return encrypted_bits
    
def test_shift_registers():
    """
    Figure out which one of the GSM A5/1 LFSRs could have produced the stream
    of output bits given by SAMPLE_LFSR_OUTPUT.
    """
    print("First GSM A5/1 LFSR matches sample output:", lfsr_matches_output(SAMPLE_LFSR_OUTPUT, A51_LFSR_0_LENGTH, A51_LFSR_0_TAPPED_BITS))
    print("Second GSM A5/1 LFSR matches sample output:", lfsr_matches_output(SAMPLE_LFSR_OUTPUT, A51_LFSR_1_LENGTH, A51_LFSR_1_TAPPED_BITS))
    print("Third GSM A5/1 LFSR matches sample output:", lfsr_matches_output(SAMPLE_LFSR_OUTPUT, A51_LFSR_2_LENGTH, A51_LFSR_2_TAPPED_BITS))
    
def lfsr_matches_output(output, lfsr_length, lfsr_tapped_bits):
    """
    Returns True if the specified linear feedback shift register could produce
    the sequence of bits specified in output, False otherwise.
    """
    starting_state = output[:lfsr_length][::-1]
    assert len(starting_state) == lfsr_length
    
    test_lfsr = ShiftRegister(starting_state, lfsr_tapped_bits)

    for i in range(len(output)):
        expected_bit = output[i]
        actual_bit = test_lfsr.get_next_output()
        if expected_bit != actual_bit:
            return False
    
    # All expected and actual output bits matched.
    return True
    
def lfsr_decrypt(ciphertext, lfsr):
    """
    Attempts to obtain the plaintext string corresponding
    to the encrypted hexadecimal string in ciphertext by xoring
    with a keystream produced by lfsr.
    Returns the resulting plaintext string.
    """
    ciphertext_bits = hex_string_to_bits(ciphertext)
    keystream_bits = lfsr.get_output_bits(len(ciphertext_bits))
    assert len(keystream_bits) == len(ciphertext_bits)
    assert keystream_bits == SAMPLE_LFSR_OUTPUT[:len(ciphertext_bits)]
    
    for i in range(LFSR_DECRYPTION_ATTEMPTS):
        potential_plaintext_bits = xor(ciphertext_bits, keystream_bits)
        potential_plaintext_str = bits_to_string(potential_plaintext_bits)
        if is_valid_message(potential_plaintext_str):
            return potential_plaintext_str
            
        keystream_bits = keystream_bits[1:] + [lfsr.get_next_output()]
    
    return None
    
def deliver_hint(recipient, hint_str):
    """
    Establish an encrypted session with the specified recipient
    and send hint_str.
    """
    initialization_response = initialize(recipient[0])
    session_token = initialization_response['token']
    
    pg = get_pg()
    p = int(pg['p'], 16)
    g = int(pg['g'], 16)

    eve_key_response_int = pow(g, X_EVE, p)
    eve_key_response = hex(eve_key_response_int)[2:] # chop off the "0x"
    
    key_received_response = send_key(recipient[0], session_token,
            eve_key_response, "Eve")
    
    (ctr_key, ctr_nonce) = get_ctr_info(X_EVE, int(initialization_response['public'], 16))
    
    initial_message = receive_msg(recipient[0], session_token)
    
    
    decrypted_message = counter_mode_encrypt(initial_message['msg'], ctr_key, initial_message['iv'], ctr_nonce)
    decrypted_message_str = bits_to_string(decrypted_message)
    print("decrypted_message_str", decrypted_message_str)
    
    hint_hex = hex(bits_to_int(string_to_bits(hint_str)))[2:]
    encrypted_hint = counter_mode_encrypt(hint_hex, ctr_key, initial_message['iv'], ctr_nonce)
    encrypted_hint_hex = hex(bits_to_int(encrypted_hint))[2:]
    
    response = send_msg(recipient[0], session_token,
            encrypted_hint_hex, initial_message['iv'])
    
    decrypted_message = counter_mode_encrypt(response['reply']['msg'], ctr_key, response['reply']['iv'], ctr_nonce)
    decrypted_message_str = bits_to_string(decrypted_message)
    print("decrypted_message_str", decrypted_message_str)
    
    
if __name__ == "__main__":
    
    assert bits_to_string(hex_string_to_bits("53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67")) == \
            "Single block msg"
            
    print("Trying Test Vector #1")
    assert counter_mode_encrypt("53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67",
            "AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E",
            "00 00 00 00 00 00 00 00",
            "00 00 00 30") == \
            hex_string_to_bits("E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8")
            
    print("Trying Test Vector #2")
    assert counter_mode_encrypt(
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F",
            "7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63",
            "C0 54 3B 59 DA 48 D9 0B",
            "00 6C B6 DB") == \
            hex_string_to_bits(
            "51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88" +
            "EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28")

    run_exchanges()
            
    test_shift_registers()

    a51_lfsr_0 = ShiftRegister(SAMPLE_LFSR_OUTPUT[:A51_LFSR_0_LENGTH][::-1], A51_LFSR_0_TAPPED_BITS)
    
    bob_plaintext = lfsr_decrypt(BOB_CIPHERTEXT, a51_lfsr_0)
    print("Got bob_plaintext:", bob_plaintext)
    
    deliver_hint(Alice, bob_plaintext)
 
    print("Exchanges complete")
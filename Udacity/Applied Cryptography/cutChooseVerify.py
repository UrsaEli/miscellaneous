#
# Dan Clark
# https://github.com/dandclark
#
# Udacity Applied Cryptography
# HW 6-3
# Cut and Choose -- Verification Step
#
# Original problem description:
#
# In this assignment, you will write the verify step
# for the bank in the cut-and-choose protocol.  
# 
# The code for the cut-and-choose protocol
# is in the `cutchoose` module
# 1) Alice generates N bills 
# for some amount.
# 2) The bills are sent to the bank.  The bank
# picks one and signs it.
# 3) Before sending it back to Alice, the bank
# asks for the random nonces for the other N-1 bills
# 4) The bank verifies the nonces and the amounts
# before sending back the signed bill
# This last step is where you will be adding your code
#

import cutchoose
from unit4_util import string_to_bits, bits_to_int, pad_to_block, bits_to_string, convert_to_bits, ASCII_BITS

def unblind_bill(blinded_bill, nonce, e, d, n):
    """
    Expects bill blinded as blinded_bill = bill * nonce^e mod n.
    A property of RSA encryption is that m^(ed) = m mod n, and it
    follows that m^(ed - 1) = 1 mod n.  Therefore we have
    bill = bill * nonce^(ed - 1) mod n
    bill = bill * nonce^(e - e) * nonce^(ed - 1) mod n
    bill = bill * nonce^e * nonce^(ed - e - 1) mod n
    bill = blinded_bill * nonce^(ed - e - 1) mod n
    
    We use the above property to unblind the bill without the use of a
    multiplicative inverse.
    """
    return (blinded_bill *  pow(nonce, e * d - e - 1, n)) % n

def _verify(bills, nonces, value):
    """
    # Returns True if all of the bills have the value specified,
    # False otherwise
    """
    print("Doing verification for", len(bills), "bills")
    for bill, nonce in zip(bills, nonces):
        unblinded_bill = unblind_bill(bill, nonce, cutchoose.BANK_PUBLIC_KEY[0],
                cutchoose._BANK_PRIVATE_KEY, cutchoose.BANK_PUBLIC_KEY[1])
        unblinded_bill_str = bits_to_string(pad_to_block(convert_to_bits(unblinded_bill), ASCII_BITS))
        unblinded_bill_value = cutchoose.bill_value(unblinded_bill_str)
        print("unblinded bill_str is", unblinded_bill_str)
        
        if not unblinded_bill_value == value:
            print("bill", unblinded_bill_str, "has value", unblinded_bill_value, "but expected", value)
            return False
    
    print("Bills passed verification")
    return True
    ###########
cutchoose._verify = _verify

def test():
    # Alice generates some bills
    bills = cutchoose.generate_bills(50)
    # and sends them to the bank.
    # The bank picks one and sends
    # back which one
    i = cutchoose.pick_and_sign_bills(bills)
    # Alice now needs to send back
    # the random nonces
    nonces = cutchoose.send_nonces(i)
    # bank checks the nonces and
    # if they pass, returns the signed bill
    signed = cutchoose.verify_bills_and_return_signed(nonces, 50)
    assert signed is not None
    assert bills[i] == pow(signed, cutchoose.BANK_PUBLIC_KEY[0], 
                           cutchoose.BANK_PUBLIC_KEY[1])

    # here, we'll try to cheat and see if we get caught
    bills = cutchoose.cheat_generate_bills(50, 100)
    i = cutchoose.pick_and_sign_bills(bills)
    nonces = cutchoose.send_nonces(i)
    signed = cutchoose.verify_bills_and_return_signed(nonces, 50)
    # there is a 1% chance we got away with this
    assert signed is None

if __name__ == "__main__":
    print("Testing...")
    test()
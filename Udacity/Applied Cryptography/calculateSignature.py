#
# Dan Clark
#
# Udacity Applied Cryptography
# HW4-04 Version 1
#
# Given a public key, and two signatures
# calculate the signature for a third message
#
# Remember that signatures are created using a
# private key, which you don't have access to
#

from math import log
from math import floor

# Public Key:
e = 65537
n = 132177882185373774813945506243321607011510930684897434818595314234725602493934515403833460241072842788085178405842019124354553719616350676051289956113618487539608319422698056216887276531560386229271076862408823338669795520077783060068491144890490733649000321192437210365603856143989888494731654785043992278251


################
# Here are two example signatures
#
# First message
m1 = 387
# first signature
s1 = 104694095966994423550399840405679271451689287439740118881968798612714798360187905616965324945306116261186514828745033919423253353071142760352995900515279740753864505327750319034602409274084867637277266750899735986681083836544151016817569622466120342654469777762743360212628271549581658814852850038900877029382

# Second message
m2 = 2
# second signature
s2 = 18269259493999292542402899855086766469838750310113238685472900147571691729574239379292239589580462883199555239659513821547589498977376834615709314449943085101697266417531578751311966354219681199183298006299399765358783274424349074040973733214578342738572625956971005052398172213596798751992841512724116639637

################
# And this is the message you need to 
# create a signature for
m3 = 774
s3 = (s1 * s2) % n # CALCULATE A SIGNATURE
# The above works because:
# s1 == m1^d
# s2 == m2^d
# m3 == 774 == 387 * 2 == m1 * m2
# s3 == m3^d == (m1 * m2) ^ d == m1^d * m2^d == s1 * s2 (mod n)
#



###############
# Code to test the signature

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

def verify_signature(e, n, m, s):
    assert m == mod_exp(s, e, n)

def test():
    verify_signature(e, n, m1, s1)
    verify_signature(e, n, m2, s2)
    verify_signature(e, n, m3, s3)

if __name__ == "__main__":
    test()
    print("Passed test.")
    
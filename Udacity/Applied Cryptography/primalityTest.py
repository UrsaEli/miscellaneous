# HW3-4 Version 1
# 
# Implement the Rabin Miller test for primality
#
from random import randrange

def mod_exp(a, b, q):
    """returns a**b % q"""
    if b == 0:
        return 1
    elif b % 2 == 0:
        return mod_exp((a ** 2) % q, b / 2, q)
    else:
        return (a * mod_exp((a ** 2) % q, (b - 1) / 2, q)) % q

def rabin_miller(n, target=128):
    """returns True if prob(`n` is composite) <= 2**(-`target`)"""
    probabilityIsComposite = 0
    while probabilityIsComposite < target:
        if not rabin_miller_check(randrange(1, n), n):
            return False
        probabilityIsComposite += 2
    return True

def rabin_miller_check(guess, n):
    """
    Returns true if n meets the primality requirements of the Rabin Miller test
    for the integer guess.
    """
    # n = (2^t)*s + 1 ; we need to find s and t.
    s = n - 1
    t = 0
    while s % 2 == 0:
        t += 1
        s /= 2
    
    # Check the first condition
    if mod_exp(guess, s, n) == 1:
        return True
    
    # If we didn't meet the first condition, check the second.
    for i in range(t):
        if mod_exp(guess, s * (2 ** i), n) == n - 1:
            return True
    
    # We didn't meet either condition so n must not be prime.
    return False
    
primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, \
        41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,  \
        97, 101, 103]
    
if __name__ == "__main__":
    for i in range(2, primes[len(primes) - 1] + 1):
        isPrime = rabin_miller(i)
        if not (isPrime == (i in primes)):
            print("For n=", i, "got rabin_miller ==",
                    isPrime, "but should be", i in primes)
            exit(-1)
    
    print("Tests passed")
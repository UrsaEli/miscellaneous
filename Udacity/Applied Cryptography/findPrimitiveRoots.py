# HW3-2 Version 1
#
# Define a procedure primitive_roots 
# that takes as input a small prime number
# and returns all the primitive roots of that number
#

# from hw3_2_util import mod_exp

def mod_exp(a, b, q):
    """returns a**b % q"""
    #################
    ## Start of your code
    if b == 0:
        return 1
    elif b % 2 == 0:
        return mod_exp((a ** 2) % q, b / 2, q)
    else:
        return (a * mod_exp((a ** 2) % q, (b - 1) / 2, q)) % q
    ## End of your code
    #################

def primitive_roots(n):
    """
    Returns all the primitive_roots of 'n'
    Requires that n is prime.
    """
    
    roots = []
    ##########
    # Start of your code
    for i in range(2, n):
        if is_primitive_root(i, n):
            roots.append(i)
    return roots
    #  End of your code
    ##########

def is_primitive_root(r, n):
    """
    Returns True if r is a primitive root of n, false otherwise.
    Requires that n is prime.
    """
    generatedNumbers = [False] * n
    for i in range(1, n):
        result = mod_exp(r, i, n)
        # If raising r to two different powers results in the same result
        # mod n, then r must not be a primitive root of n (assuming n is prime).
        if generatedNumbers[result - 1]:
            return False
        else:
            generatedNumbers[result - 1] = True
    return True
    
def test():
    assert primitive_roots(3) == [2]
    assert primitive_roots(5) == [2, 3]
    assert primitive_roots(7) == [3, 5]
    assert primitive_roots(11) == [2,6,7,8]
    assert primitive_roots(13) == [2,6,7,11]
    assert primitive_roots(17) == [3, 5, 6, 7, 10, 11, 12, 14]
    print("tests pass")

if __name__ == "__main__":
    test()
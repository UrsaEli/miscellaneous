# Unit3-13 Version 1
# 
# Write a function, mod_exp that returns
# `a**b % q` and has a runtime that is linear
# in the size of `b` - where the size of `b`
# is the number of bits

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

def test():
    # testing runtime performance in general is hard, but in this case
    # its enough to try large inputs.  For example on my machine naively
    # running 100 **  488778445455 % 543 takes a really long time
    # but mod_exp(100, 488778445455, 543) finishes pretty quick
    # Timings will be different on your machine if you are testing
    # locally, but in our environment, your routine should
    # be able to run through 1000 calculations in less then .5 seconds
    from time import time
    start = time()
    for _ in range(1000):
        t = mod_exp(100, 488778445455, 543)
    print(t)
    finish = time()
    assert t == 49
    assert finish - start < 0.5
    print("Test passed")

# uncomment to test
test()
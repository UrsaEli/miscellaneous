##
#
# Dan Clark
# thedanclark@gmail.com
# 31 January 2014
#

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def totient(n):
    assert n >= 1
    totient = 1
    for i in range(2, n):
        if gcd(n, i) == 1:
            totient += 1
    return totient
    
if __name__ == "__main__":
    print(totient(9))
    print(totient(831))
    print(gcd(12,28))
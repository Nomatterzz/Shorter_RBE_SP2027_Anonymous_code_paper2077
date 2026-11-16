"""Outward-rounded integer interval arithmetic; no floating point."""
from fractions import Fraction
from math import isqrt

def ceildiv(a,b): return -(-a//b)

def atan_inverse(d,P):
    S=1<<P; lo=hi=0; power=d; k=0
    while True:
        den=(2*k+1)*power; a,b=S//den,ceildiv(S,den)
        if k%2:lo-=b;hi-=a
        else:lo+=a;hi+=b
        k+=1;power*=d*d
        rem=ceildiv(S,(2*k+1)*power)
        if rem<=1:
            if k%2:lo-=rem
            else:hi+=rem
            return lo,hi

def pi_interval(P):
    a,b=atan_inverse(5,P);c,d=atan_inverse(239,P)
    return 16*a-4*d,16*b-4*c

def exp_negative_interval(zlo,zhi,P):
    assert 0<=zlo<=zhi
    S=1<<P;r=0
    while zhi>((S>>3)<<r):r+=1
    xlo,xhi=zlo>>r,ceildiv(zhi,1<<r)
    lo=hi=tlo=thi=S;k=0
    while True:
        k+=1;tlo=tlo*xlo//(S*k);thi=ceildiv(thi*xhi,S*k)
        if k%2:lo-=thi;hi-=tlo
        else:lo+=tlo;hi+=thi
        if thi<=1:
            rem=ceildiv(thi*xhi,S*(k+1))
            if (k+1)%2:lo-=rem
            else:hi+=rem
            break
        assert k<P+32
    lo,hi=max(0,lo),min(S,hi)
    for _ in range(r):lo=lo*lo//S;hi=ceildiv(hi*hi,S)
    return max(0,lo),min(S,hi)

def log_interval(x,terms=180):
    assert x>=1;e=0
    while x>=2:x/=2;e+=1
    def reduced(y):
        t=(y-1)/(y+1);a=t;total=Fraction(0)
        for k in range(terms):total+=a/(2*k+1);a*=t*t
        low=2*total
        return low,low+2*a/((2*terms+1)*(1-t*t))
    a,b=reduced(x);c,d=reduced(Fraction(2))
    return a+e*c,b+e*d

def sqrt_interval(x,P=384):
    k=isqrt(x<<(2*P));return Fraction(k,1<<P),Fraction(k+1,1<<P)

'''
# File : Get_PUPR.py
# Author : Hongpei Lin
# Date : 20191023
# Purpose : Generate primes p and q, and write e and n to a public file;
#           write Phi_n to another file that is private
#           In this project, I let e=65537
'''

import random
import time

#Algorithm GCD to compute greatest common divisor
def gcd(a,b):
    while b!=0:
        y=b
        b=a%b
        a=y
    return a

#A quickly multiply algorithm with modding n
def Qmul(a,b,n):
    r=0
    while b:
        if b&1:
            r=(r+a)%n
        b=b>>1
        a=(a<<1)%n
    return r

#A quidckly exponential algorithm with modding n
def QPow(a,x,n):
    result=1
    while x:
        if x&1:
            result=(result*a)%n
        x=x>>1
        a=(a*a)%n
    return result

#Find the number = (n-1)/2^k
def Find_q(n):
    while not n&1:
        n=n>>1
    return n

#Miller Rabin algorithm
def Miller_Rabin(a,n):
    q=Find_q(n-1)
    aq=QPow(a,q,n)
    #final condition,q=n-1
    while q<n:
        if aq==1 or aq==-1:
            return True
        #make aq = aq(q*2^j)
        aq=QPow(aq,2,n)
        q=q<<1
    return False

#A quickly algorithm to make a odd number
def Build_Random_Odd(nbit):
    #hightest bit = 1
    number=1
    #every bit value = 0 or 1
    while nbit-2:
        number=(number<<1)|random.randint(0,1)
        nbit=nbit-1
    #lowest bit = 1, make it is odd
    number=(number<<1)|1
    return number

#A algorithm to test whether a number is a prime
def Judge_Prime(n):
    #using Miller Rabin to test is in 10 times
    t=10
    while t:
        t-=1
        a=random.randint(2,n-1)
        if not Miller_Rabin(a,n):
            return False
    return True

#A algrothm to build prime p and q, and gcd(e,Phi(n))=1
#because Phi(n)=(p-1)*(q-1), if gcd(e,Phi(n))!=1, e must be the factor with p-1 or q-1
def Build_Prime(e):
    while True:
        i=0
        p_flag=False
        p_bit=random.randint(512,1024)
        p=Build_Random_Odd(p_bit)
        #if it is not a prime, maybe it plus 2 will be
        #try 100 times, meaning plus 100
        while i<100:
            if Judge_Prime(p):
                p_flag=True
                break
            else:
                p=p+2
                i+=1
                continue
        #if (p-1) don't coprime e, make another p again
        if p_flag and gcd(e,p-1)==1:
            break
        else:
            continue
    while True:
        j=0
        q_flag=False
        q_bit=random.randint(512,1024)
        q=Build_Random_Odd(q_bit)
        while j<100:
            if Judge_Prime(q):
                q_flag=True
                break
            else:
                q=q+2
                j+=1
                continue
        if q_flag and gcd(e,q)==1:
            break
        else:
            continue
    return p,q

starttime = time.time()
e=65537
p,q=Build_Prime(e)
n=p*q
Phi_n=(p-1)*(q-1)

#write e and n to a public file
fpu=open("publicfile.txt","w+")
fpu.write(str(e)+'\n')
fpu.write(str(n))
fpu.close()

#write  Phi(n) to a private file
fpr=open("privatefile.txt","w+")
fpr.write(str(Phi_n))
fpr.close()

endtime = time.time()
#running time
print("running time")
print(endtime - starttime)
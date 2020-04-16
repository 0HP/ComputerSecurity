'''
# File : RSA.py
# Author : Hongpei Lin
# Date : 20191023
# Purpose : RSA
'''
import re
import codecs
import hashlib

def egcd(a,b):
    r0,r1,s0,s1,t=1,0,0,1,b
    while b:
        q,a,b=a//b,b,a%b
        r0,r1=r1,r0-q*r1
        s0,s1=s1,s0-q*s1
    if r0<0:
        r0=r0%t
    return r0

def QPow(a,x,n):
    result=1
    while x:
        if x&1:
            result=(result*a)%n
        x=x>>1
        a=(a*a)%n
    return result

#Get public key in a public flie
def Get_PuKey(puf):
    fpu=open(puf,"r")
    l=[]
    for line in fpu.readlines():
        l.append(int(line))
    fpu.close()
    e,n=l[0],l[1]
    return e,n

#Get private key in a private file
def Get_PrKey(puf,prf):
    e,n=Get_PuKey(puf)
    fpr=open(prf,"r")
    Phi_n=int(fpr.read())
    fpr.close()
    d=egcd(e,Phi_n)
    return d,n

#make a string become bitstream
def Str_to_Byte(s):
    news=""
    for i in s:
        news=news+"{:08b}".format(ord(i))
    return news

#block the plain, every block has 1024 bits
#input a bitstream,output a list
def BlockPlain(n):
    nlist=[]
    nlength=len(n)
    if not nlength>1024:
        nlist.append(n)
        return nlist
    i=0
    while i>nlength:
        nlist.append(n[i:i+1024])
        i+=1024
    nlist.append(n[i:])
    return nlist

#RSA encrypt and decrypt, accordings using public key or private key
def RSA_Encrypt(s,e,n):
    news=Str_to_Byte(s)
    Clist=BlockPlain(news)
    Cstring=""
    for i in Clist:
        value=int(i,2)
        encryption=QPow(value,e,n)
        encryption=bin(encryption)[2:]
        while len(encryption)%8!=0:
            encryption="0"+encryption
        Cstring=Cstring+encryption
    Crylist=re.findall(r'.{8}',Cstring)
    s1=""
    for i in Crylist:
        s1+=chr(int(i,2))
    return s1

#encrypt plaintext
def EncryptText(puf):
    PlainTextFile=input("Please input the filename you wanna encrypt\n")
    fo=codecs.open(PlainTextFile,"r",encoding='utf-8')
    PlainText=fo.read()
    fo.close()
    e,n=Get_PuKey(puf)
    Encrypttext=RSA_Encrypt(PlainText,e,n)

    fw=codecs.open("EncryptText.txt","w",encoding='utf-8')
    fw.write(Encrypttext)
    fw.close()
    return True

#decrypt
def DecryptText(puf,prf):
    d,n=Get_PrKey(puf,prf)
    EncryptFile=input("Please input the filename you wanna decrypt\n")
    fo=codecs.open(EncryptFile,"r",encoding='utf-8')
    EncryptFileText=fo.read()
    fo.close()
    Decrypttext=RSA_Encrypt(EncryptFileText,d,n)

    fw=codecs.open("DecryptText.txt","w+",encoding='utf-8')
    fw.write(RSA_Encrypt(EncryptFileText,d,n))
    fw.close()
    return True

#Digital signatrue
def SignaTrue(puf,prf):
    d,n=Get_PrKey(puf,prf)
    message=input("Please input the filename of the message!\n")
    fr=codecs.open(message,"rb")
    Mstring=fr.read()
    fr.close()

    MHash=hashlib.sha3_256()
    MHash.update(Mstring)

    Sign=RSA_Encrypt(MHash.hexdigest(),d,n)

    fw=codecs.open("Signatrue.txt","w+",encoding='utf-8')
    fw.write(Sign)
    fw.close()
    return True

#Authentication
def JudgeSign(puf):
    e,n=Get_PuKey(puf)
    sign=input("Please input the filename of the signatrue!\n")
    message=input("Please input the filename of the message!\n")

    fr=codecs.open(message,"rb")
    Mstring=fr.read()
    fr.close()

    MHash=hashlib.sha3_256()
    MHash.update(Mstring)

    fs=codecs.open(sign,"r",encoding='utf-8')
    sign=fs.read()
    fs.close()

    Auth=RSA_Encrypt(sign,e,n)

    if Auth==MHash.hexdigest():
        return True
    else:
        return False

def __main__():
    select="Please select the functions\n"
    encrypt="0:Encrypt\n"
    decrypt="1:Decrypt\n"
    Sign="2:Signature\n"
    Authentication="3:Authentication\n"
    out="Other:Exit\n"
    pukeyfile="publicfile.txt"
    prkeyfile="privatefile.txt"

    while True:
        project=input(select+encrypt+decrypt+Sign+Authentication+out)
        if project=="0":
            if EncryptText(pukeyfile):
                print("Encrypt Successfully!")
                continue
            else:
                print("Encrypt Failed!")
                continue
        elif project=="1":
            if DecryptText(pukeyfile,prkeyfile):
                print("DecryptText Successfully!")
                continue
            else:
                print("Encrypt Failed!")
                continue
        elif project=="2":
            if SignaTrue(pukeyfile,prkeyfile):
                print("Signatrue Successfully!")
                continue
            else:
                print("Signatrue Failed!")
                continue
        elif project=="3":
            if JudgeSign(pukeyfile):
                print("Authentication Successfully!")
                continue
            else:
                print("Authentication Failed!")
                continue
        else:
            break

if __name__=="__main__":
    __main__()
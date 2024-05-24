#DFA on 16th round of DES: 32 fausse plaintext obtained
#we want to recover the sub-key used in the 16th round of DES
LFC16=[]
fichier = open("chiffre.txt", "r")
for ligne in fichier:
    l=ligne.strip()
    l=l.replace(" ","")
    LFC16.append(l)
fichier.close()
from collections import Counter

IPtable = (58, 50, 42, 34, 26, 18, 10, 2,
           60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6,
           64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17,  9, 1,
           59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5,
           63, 55, 47, 39, 31, 23, 15, 7)
#Permitation initiale

P_box =(16, 7,20,21,29,12,28,17,
        1 ,15,23,26, 5,18,31,10,
        2 ,8 ,24,14,32,27, 3, 9,
        19,13,30, 6,22,11, 4,25) 
#Permutation box
#32
Pinvtable=(9, 17, 23, 31, 13, 28, 2, 18,
      24, 16, 30, 6, 26, 20, 10, 1,
      8, 14, 25, 3, 4, 29, 11, 19,
      32, 12, 22, 7, 5, 27, 15, 21)

E_box = (32,1,2,3,4,5,
        4,5,6,7,8,9,
        8,9,10,11,12,13,
        12,13,14,15,16,17,
        16,17,18,19,20,21,
        20,21,22,23,24,25,
        24,25,26,27,28,29,
        28,29,30,31,32,1,)
#expansion

sBox = 8*[64*[0]]
 
sBox[0] = (14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
            0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
            4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
           15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13)
 
sBox[1] = (15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
            3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
            0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
           13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9)
 
sBox[2] = (10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
           13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
           13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
            1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12)
 
sBox[3] = ( 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
           13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
           10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
            3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14)
 
sBox[4] = ( 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
           14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
            4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
           11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3)
 
sBox[5] = (12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
           10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
            9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
            4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13)
 
sBox[6] = ( 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
           13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
            1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
            6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12)
 
sBox[7] = (13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
            1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
            7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
            2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11)

Cjuste="7669ae88f4184d48" #chiffre juste

def convert(character):
    return bin(int(character,16)) 
#hexa to bin

# list to bin
def ltb(liste):
    chr=""
    for i in liste:
        chr+=str(i)
    return chr

def xor(A,B):
    #A,B deux characters binaires
    return ltb([ord(a) ^ ord(b) for a,b in zip(A,B)])

def regularise(k,n):
    n=n[2:]
    if len(n)<k:
        n="0"*(k-len(n))+n
    return n  

def permutation(L,table):
    l="0"+L
    F=""
    for item in table:
        F+=l[item]
    return F
#Inversion 

def S_i(L,i): #6 bits to 4 bits
    r=2*int(L[0])+int(L[5])
    c=int(L[1]+L[2]+L[3]+L[4],2)
    n=bin(sBox[i][16*r+c])
    number=regularise(4,n)
    return ltb(number)

cjuste=regularise(64,convert(Cjuste))

LFC2=[]
for item in LFC16:
    item=convert(item)
    LFC2.append(regularise(64,item))
#LFC16 to binary
#list of fault chiffrement in binary

L16R16=permutation(cjuste,IPtable) #L16+R16
#permutation initiale de chiffrement juste=L16+R16

L16=L16R16[:32]
R16=L16R16[32:]

R15=R16

inv=[]
for item in LFC2:
    inv.append(permutation(item,IPtable))
gauche=[]
droite=[]
for item in inv:
    gauche.append(item[:32]) #L16' of each faute message
    droite.append(item[32:]) #R16' of each faute message
#inverse the list of faute message for obtaining L16+R16 for every faute message

faute=[]
for item in droite:
    faute.append(xor(item,R15))
#the faute(32bits) adding to each R15
#faute

A=[]
for item in gauche:
    A.append(xor(item,L16))
#L16+L16'

Ainv=[]
for item in A:
    Ainv.append(permutation(item,Pinvtable))
#P^-1(L16+L16')

EC=[]
for item in faute:
    EC.append(permutation(item,E_box))
#List Expansion of C

#Expansion of R15
ER15=permutation(R15,E_box)

def IN_OUT(k):    
    L=[]
    for i in range(32):
        if Ainv[i][k*4:k*4+4]!='0000':
            L.append((Ainv[i][k*4:k*4+4],(EC[i][k*6:k*6+6])))
    return L

def possibility(char):
    RE6=[regularise(6,bin(i)) for i in range(2**6)]
    L=[]
    if len(char)==6:
        for i in RE6:
            for j in RE6:
                if xor(i,j)==char:
                    L.append((i,j))
    return L    
def table(k):
    L=[]
    liste=IN_OUT(k)
    for item in liste:
        bit4=item[0]
        bit6=item[1]
        l=possibility(bit6)
        for couple in l:
            if xor(S_i(couple[0],k),S_i(couple[1],k))==bit4:
                L.append(int(couple[0],2))
                L.append(int(couple[1],2))
    return L

L=[]
for i in range(0,8):
    Liste=table(i)
    L.append(max(Liste,key=Liste.count))
char=""
for i in L:
    b=bin(i)
    char+=regularise(6,b)
K16=hex(int(xor(char,ER15),2))[2:] 
K16
#K16 is the 48-bits key obtained
#to get the 56-bits key, we need to use the inverse of the key schedule algorithm

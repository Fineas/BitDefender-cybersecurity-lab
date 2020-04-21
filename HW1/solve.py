from pwn import *
import string
import itertools

# lol, bruteforce
def generate_PASSWORDs(length=8):
    chars = "aOpWqnRsEhXyCvJt"
    for item in itertools.product(chars, repeat=length):
        yield "".join(item)

BUFF1 = "aOpWqnRsEhXyCvJt"
BUFF2 = [0x2,0x3,0x6,0xA,0x1,0x4,0xF,0xB,0x9,0xE,0x5,0xD,0x7,0x8,0xC,0x00]

rol = lambda val, r_bits: \
    (val << r_bits%32) & (2**32-1) | \
    ((val & (2**32-1)) >> (32-(r_bits%32)))

def generate_username_token(USERNAME):
    i=0
    ID = 0
    while USERNAME[i] != '\x00':
        #   ROL    ID,0x5
        ID = rol(ID,5)
        print hex(ID)
        #   XCHG   AH, AL
        al = ID%0x100
        ah = (ID/0x100) % 0x100
        ID = ID / 0x10000
        if al == 0 and ah == 0:
          ID = hex(ID) + '00' + '00'
        elif al == 0:
          ID = hex(ID) + '00' + hex(ah)[2:]
        elif ah == 0:
          ID = hex(ID) + hex(al)[2:] + '00'
        elif al <= 15:
          ID = hex(ID) + '0' + hex(al)[2:] + hex(ah)[2:]
        elif ah <= 15:
          ID = hex(ID) + hex(al)[2:] + '0' + hex(ah)[2:]
        else:
          ID = hex(ID) + hex(al)[2:] + hex(ah)[2:]
        ID = int(ID,16)
        print hex(ID)
        #   XOR EAX, 0xc8fa7b6e
        ID = ID ^ 0xc8fa7b6e
        print hex(ID)
        #   ADD EAX, ECX
        ID += ord(USERNAME[i])
        print hex(ID)
        #   INC EDX
        i += 1
    return ID

def test_PASSWORD(PASSWORD):
  T = 0
  pass_idx = 0

  while True:
    index = 0
    while True:
      if BUFF1[index] == PASSWORD[pass_idx]:
        break
      index += 1
      if index > 0x10:
        break
    if index == 16:
      break
    pass_idx += 1
    # print 'T=',T,'index=',index,'pass_idx=',pass_idx
    T = ( (T << 4) | (BUFF2[index] & 0xF) ) ^ 0xa
    if pass_idx >= 8:
      return T
  return 0

def generate_password(token):
  dictionary = {
    '8':'a',
    '9':'O',
    'c':'p',
    '0':'W',
    'b':'q',
    'e':'n',
    '5':'R',
    '1':'s',
    '3':'E',
    '4':'h',
    'f':'X',
    '7':'y',
    'd':'C',
    '2':'v',
    '6':'J',
    'a':'t'
  }
  password = ''
  for i in token[2:]:
    password += dictionary[i]
  return password

# ==============================================

NAME = 'fineasilag' # input the desired username
token = generate_username_token(NAME+'\x00')
print 'Name=',NAME,'| Token=',hex(token)
PASS = generate_password(hex(token))
print 'PASS=',PASS


# print 'PASS_Tok= aOpWqnRs',hex(test_PASSWORD('aOpWqnRs'))
# print 'PASS_Tok= EhXyCvJt',hex(test_PASSWORD('EhXyCvJt'))

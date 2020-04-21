from pwn import *
import string
from ctypes import *

# Rotate left. Set max_bits to 8.
rol = lambda val, r_bits, max_bits=8: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
# Rotate right. Set max_bits to 8.
ror = lambda val, r_bits, max_bits=8: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def decrypt_txt(data):
    decrypted_txt = ''
    uppercase_encoded = []
    lowercase_encoded = []
    digits_encoded = []
    other_encoded = []
    # generate dictionary
    for i in string.uppercase:
        uppercase_encoded.append( chr( rol( ((-101-ord(i)) | 0x20), 2 ) &0xff ))
    for i in string.lowercase:
        lowercase_encoded.append( chr( rol( ((-37-ord(i)) ^ 0x20), 2 ) &0xff ))
    for i in string.digits:
        digits_encoded.append( chr( rol( (105-ord(i)), 2) ))
    for i in range(0xff+1):
        other_encoded.append(chr( rol(i,2)&0xff ))
    
    # print uppercase_encoded
    # print lowercase_encoded
    # print digits_encoded
    # print other_encoded

    # decode
    for i in data:
        if i in uppercase_encoded:
            decrypted_txt += chr(0x41 + uppercase_encoded.index(i))
        elif i in lowercase_encoded:
            decrypted_txt += chr(0x61 + lowercase_encoded.index(i))
        elif i in digits_encoded:
            decrypted_txt += chr(0x30 + digits_encoded.index(i))
        else:
            decrypted_txt += chr(other_encoded.index(i))

    # print decrypted_txt
    return decrypted_txt

def decrypt_png(data):
    decrypted_png = ''
    for i in data:
        decrypted_png += chr(((ror(ord(i),4))^0x44)&0xff)
    return decrypted_png

def decrypt_jpg(data):
    decrypted_jpg = ''
    g_buf = "AkjsSHwiE27.[$+#"
    for i in range(0,len(data),2):
        v1 = data[i]
        v2 = data[i+1]

        for j in range(0xff+1):
            if g_buf[j & 0xf] == v2 and g_buf[j >> 4] == v1:
                decrypted_jpg += chr(j)
                break
    return decrypted_jpg

def decrypt_docx(data):
    decrypted_docx = ''
    for i in data:
        b = (((ord(i) ^ 0xc1) + 0x4d ) ^ 0x8b) - 5
        b &= 0xff
        decrypted_docx += chr(b)
    return decrypted_docx

def decrypt_pdf(data):
    decrypted_pdf = ''
    libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
    libc.srand(len(data))

    # ORIGINAL = \x25\x50\x44\x46\x2d
    # ENCRYPTED = \x82\xc5\x63\xb9\xa5
    for i in data:
        decrypted_pdf += chr((libc.rand() ^ ord(i))&0xff)

    return decrypted_pdf


# DECRYPT .DOCX
f1 = open('test_encrypt/undec/Qiew_overview.docx','r')
f2 = open('test_encrypt/dec/decrypted.docx','w')
data_e = f1.read()
data_d = decrypt_docx(data_e)
f2.write(data_d)
f2.close()
f1.close()

# DECRYPT .TXT
f1 = open('test_encrypt/undec/olly.txt','r')
f2 = open('test_encrypt/dec/decrypted.txt','w')
data_e = f1.read()
data_d = decrypt_txt(data_e)
f2.write(data_d)
f2.close()
f1.close()

# DECRYPT .TXT
f1 = open('test_encrypt/undec/64bit_memory.png','r')
f2 = open('test_encrypt/dec/decrypted.png','w')
data_e = f1.read()
data_d = decrypt_png(data_e)
f2.write(data_d)
f2.close()
f1.close()

# DECRYPT .JPG
f1 = open('test_encrypt/undec/Drawing1.jpg','r')
f2 = open('test_encrypt/dec/decrypted.jpg','w')
data_e = f1.read()
data_d = decrypt_jpg(data_e)
f2.write(data_d)
f2.close()
f1.close()

# DECRYPT .PDF
f1 = open('test_encrypt/undec/cpu.pdf','r')
f2 = open('test_encrypt/dec/decrypted.pdf','w')
data_e = f1.read()
data_d = decrypt_pdf(data_e)
f2.write(data_d)
f2.close()
f1.close()
# !!!
# NOTE this soltion only allows you to send 1 message because when the dll is exited the program will crash (some adjustments need to be done to the patch in order to work well)
# !!!

'''
plan:
void convert(char *num) {
    for(int i = 0; i < 100; i++){
        if (num[i] == 'a' && num[i+1] == 'n' && num[i+2] == 'a'){
            num[i] = 'i';
            num[i+1] = 'o';
            num[i+2] = 'n';
            break;
        }
    }
}

asm:
convert(char*):
        push    ebp
        mov     ebp, esp
        sub     esp, 16
        mov     DWORD PTR [ebp-4], 0
.L4:
        cmp     DWORD PTR [ebp-4], 99
        jg      .L5
        mov     edx, DWORD PTR [ebp-4]
        mov     eax, DWORD PTR [ebp+8]
        add     eax, edx
        movzx   eax, BYTE PTR [eax]
        cmp     al, 97
        jne     .L3
        mov     eax, DWORD PTR [ebp-4]
        lea     edx, [eax+1]
        mov     eax, DWORD PTR [ebp+8]
        add     eax, edx
        movzx   eax, BYTE PTR [eax]
        cmp     al, 110
        jne     .L3
        mov     eax, DWORD PTR [ebp-4]
        lea     edx, [eax+2]
        mov     eax, DWORD PTR [ebp+8]
        add     eax, edx
        movzx   eax, BYTE PTR [eax]
        cmp     al, 97
        jne     .L3
        mov     edx, DWORD PTR [ebp-4]
        mov     eax, DWORD PTR [ebp+8]
        add     eax, edx
        mov     BYTE PTR [eax], 105
        mov     eax, DWORD PTR [ebp-4]
        lea     edx, [eax+1]
        mov     eax, DWORD PTR [ebp+8]
        add     eax, edx
        mov     BYTE PTR [eax], 111
        mov     eax, DWORD PTR [ebp-4]
        lea     edx, [eax+2]
        mov     eax, DWORD PTR [ebp+8]
        add     eax, edx
        mov     BYTE PTR [eax], 110
        nop
        jmp     .L5
.L3:
        add     DWORD PTR [ebp-4], 1
        jmp     .L4
.L5:
        nop
        leave
        ret
'''

from pwn import *

patch = asm("""
push    ebp
mov     ebp, esp
sub     esp, 16
mov     DWORD PTR [ebp-4], 0
.L4:
cmp     DWORD PTR [ebp-4], 99
jg      .L5
mov     edx, DWORD PTR [ebp-4]
mov     eax, DWORD PTR [ebp+8]
add     eax, edx
movzx   eax, BYTE PTR [eax]
cmp     al, 97
jne     .L3
mov     eax, DWORD PTR [ebp-4]
lea     edx, [eax+1]
mov     eax, DWORD PTR [ebp+8]
add     eax, edx
movzx   eax, BYTE PTR [eax]
cmp     al, 110
jne     .L3
mov     eax, DWORD PTR [ebp-4]
lea     edx, [eax+2]
mov     eax, DWORD PTR [ebp+8]
add     eax, edx
movzx   eax, BYTE PTR [eax]
cmp     al, 97
jne     .L3
mov     edx, DWORD PTR [ebp-4]
mov     eax, DWORD PTR [ebp+8]
add     eax, edx
mov     BYTE PTR [eax], 105
mov     eax, DWORD PTR [ebp-4]
lea     edx, [eax+1]
mov     eax, DWORD PTR [ebp+8]
add     eax, edx
mov     BYTE PTR [eax], 111
mov     eax, DWORD PTR [ebp-4]
lea     edx, [eax+2]
mov     eax, DWORD PTR [ebp+8]
add     eax, edx
mov     BYTE PTR [eax], 110
nop
jmp     .L5
.L3:
add     DWORD PTR [ebp-4], 1
jmp     .L4
.L5:
nop
leave
ret
""")

patch = patch.encode('hex')
t = iter(patch)
patch = ' '.join(a+b for a,b in zip(t, t))
patch = patch.split(' ')
for i in range(len(patch)/16+1):
        print ' '.join(patch[i*16:(i+1)*16])
print 'LEN=',len(patch)

###################### insert the sequence from above into the .dll to replace "ana" with "ion"

# push esi = 56
# call function = E8 52 FF FF FF
# call message_box = 6A 00 68 B0 18 00 10 56 6A 00 FF 15 88 18 00 10
# return from function = 5F 5E 5B 5D C2 08 00

patch2 = '56 E8 52 FF FF FF 6A 00 68 B0 18 00 10 56 6A 00'
patch2 += 'FF 15 88 18 00 10 5F 5E 5B 5D C2 08 00'

###################### insert the patch from above inside the MessageSend function to invoke the prevous patch on the payload
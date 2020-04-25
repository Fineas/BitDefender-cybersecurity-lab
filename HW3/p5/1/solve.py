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
for i in 
print len(patch)

# because there are 0x10 bytes between MessengerSend and DllMain, I will use this space to shift the call to MessageBox and the function prologue lower thus gaining new space for a call to my function which replaces ana with ion
# 16 - 5
# 6A 00 68 B0 18 00 10 56 6A 00 FF 15 88 18 00 10
# 5F 5E 5B 5D C2 08 | 00 CC CC CC CC CC CC CC B8 01

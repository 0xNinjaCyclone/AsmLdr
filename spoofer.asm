;--------------------------------------------------------------;
;   Author  => Abdallah Mohamed ( 0xNinjaCyclone )             ;
;   Email   => elsharifabdallah53@gmail.com                    ;
;   Date    => March 11, 2025 / 05:10AM                        ;
;   Title   => Indirect syscall / Stack Spoofing               ;
;   Note    => This code is part of a separate, priv8 project  ;
;--------------------------------------------------------------;

INVALID_SSN   EQU 0FFFFh
MAX_CHAIN_LEN EQU 20h

.data

extern hNtDll:qword
g_wSysCallNumber WORD  INVALID_SSN
g_pSysCallStub   QWORD 0h
g_pSpooferStub   QWORD 0h
g_pSpooferFake   QWORD 0h
g_ulFixesLen     QWORD 0h
g_pSpooferReg    QWORD MAX_CHAIN_LEN dup( 0h )
g_pSpooferFixes  QWORD MAX_CHAIN_LEN dup( 0h )

.code

;-------------------------------------------------------------------;
; => LPVOID GetNtDLLText(                                           ;
;							DWORD *dwpTextSize /* out */            ;
;						);                                          ;
;                                                                   ;
; => Returns a pointer to NtDLL text section                        ;
;-------------------------------------------------------------------;
GetNtDLLText proc
	;mov rax, qword ptr gs:[60h]
	;mov rax, qword ptr [rax + 18h]
	;mov rax, qword ptr [rax + 20h]
	;mov rax, qword ptr [rax]
	;mov rax, qword ptr [rax + 20h]    ; NtDLL Base
	mov rax, hNtDLL
	xor r11, r11
	xor r12, r12
	mov r12d, dword ptr [rax + 3Ch]
	add r12, rax                      ; NT HEADERS
	add r12, 108h                     ; Section headers (points to .text)
	mov r11d, dword ptr [r12 + 8h]    ; Section->Misc.VirtualSize
	mov dword ptr [rcx], r11d         ; Set ulpTextSize
	xor r11, r11
	mov r11d, dword ptr [r12 + 0Ch]   ; Section->VirtualAddress (RVA)
	add rax, r11                      ; .Text Address
	ret
GetNtDLLText endp

;-------------------------------------------------------------------;
; => NTSTATUS InitSysCall();                                        ;
; => Initializes g_pSysCallStub and g_pSpooferStub                  ;
;-------------------------------------------------------------------;
InitSysCall proc
	push 0h
	mov rcx, rsp
	call GetNtDLLText
	xchg rax, rdx
	xor rax, rax
	mov rcx, 2h
	push rsi
	push rdi
	find_stubs:
	jrcxz InitSysCallSuccess
	mov esi, dword ptr [rdx + rax]
	mov rdi, g_pSysCallStub
	test rdi, rdi
	jnz skip_sys
	cmp esi, 0CDC3050Fh
	jne skip_sys
	lea rdi, [rdx + rax]
	mov g_pSysCallStub, rdi
	dec rcx
	skip_sys:
	mov rdi, g_pSpooferStub
	test rdi, rdi
	jnz skip_spoof
	cmp si, 23FFh
	jne skip_spoof
	lea rdi, [rdx + rax]
	mov g_pSpooferStub, rdi
	dec rcx
	skip_spoof:
	inc rax
	cmp rax, [rsp + 10h]
	jne find_stubs
InitSysCall endp

InitSysCallSuccess proc
	pop rdi
	pop rsi
	pop rax
	xor rax, rax
	neg rcx
	sbb rax, rax
	ret
InitSysCallSuccess endp

;-------------------------------------------------------------------;
; => VOID PrepareSysCall(WORD wSSN);                                ;
; => Sets the desired Syscall Service Number to g_wSysCallNumber    ;
;-------------------------------------------------------------------;
PrepareSysCall proc
	mov g_wSysCallNumber, cx
	ret
PrepareSysCall endp

;-------------------------------------------------------------------;
; => NTSTATUS SysCallExec(...);                                     ;
; => Invokes a Specified Syscall with spoofing the stack            ;
;-------------------------------------------------------------------;
SysCallExec proc
	xor rax, rax	
	mov r11, g_ulFixesLen
	cmp r11, MAX_CHAIN_LEN
	jz InvalidCall
	lea r10, [g_pSpooferReg]
	lea r10, [r10 + r11 * 8]
	mov [r10], rbx
	lea r10, [g_pSpooferFixes]
	lea r10, [r10 + r11 * 8]
	mov rax, g_pSpooferStub
	test rax, rax
	jz InvalidCall
	pop r11
	mov [r10], r11
	inc [g_ulFixesLen]
	lea rbx, qword ptr [SpoofReturnBack]
	mov g_pSpooferFake, rbx
	lea rbx, g_pSpooferFake
	sub rsp, 20h
	push rax
	mov r10, rcx
	xor rax, rax
	mov ax, g_wSysCallNumber
	cmp ax, INVALID_SSN
	jz InvalidCall
	lea r12, qword ptr [InvalidCall]
	mov r11, g_pSysCallStub
	test r11, r11
	cmovna r11, r12
	jmp qword ptr r11
SysCallExec endp

InvalidCall proc
	not rax
	ret
InvalidCall endp

;-------------------------------------------------------------------;
; => <SpoofedCallReturnData> SpoofReturnBack();                     ;
; => Fixup a spoofed stack                                          ;
; => Returns back the spoofed call output                           ;
;-------------------------------------------------------------------;
SpoofReturnBack proc
	dec [g_ulFixesLen]
	mov rcx, g_ulFixesLen
	lea rbx, [g_pSpooferReg]
	mov rbx, [rbx + rcx * 8]
	lea rdx, [g_pSpooferFixes]
	lea rdx, [rdx + rcx * 8]
	add rsp, 20h
	jmp qword ptr [rdx]
SpoofReturnBack endp

;------------------------------------------------------------------------------------;
; => <SpoofedCallReturnData> SpoofCall(p1, p2, p3, p4, func, p5, so on ..)           ;
; => Calling a function with spoofing the stack                                      ;
; => Taken Paramters are the `func` params except the fifth, it is the func address  ;
; => Returns back the spoofed call (`func`) output                                   ; 
;------------------------------------------------------------------------------------;
SpoofCall proc
	mov r10, g_pSpooferStub
	test r10, r10
	jnz spoof_start
	push rdi
	push rcx
	push 0h
	mov rcx, rsp
	call GetNtDLLText
	pop rcx
	mov rdi, rax
	mov ax, 23FFh
	repne scasw
	lea r10, qword ptr [rdi - 2h]
	mov g_pSpooferStub, r10
	pop rcx
	pop rdi
	spoof_start:
	xor rax, rax
	mov r12, g_ulFixesLen
	cmp r12, MAX_CHAIN_LEN
	je InvalidCall
	lea r11, [g_pSpooferReg]
	lea r11, [r11 + r12 * 8]
	mov [r11], rbx
	lea r11, [g_pSpooferFixes]
	lea r11, [r11 + r12 * 8]
	pop rax
	mov [r11], rax
	inc [g_ulFixesLen]
	pop rbx
	mov rbx, [SpoofReturnBack]
	mov g_pSpooferFake, rbx
	lea rbx, g_pSpooferFake
	sub rsp, 20h
	push r10
	jmp qword ptr [rsp + 20h]
SpoofCall endp

end
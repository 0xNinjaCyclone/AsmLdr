
.code

; Get length of ansi string
; Input  = RDI -> Address of the string
; Output = RCX 
str_getlen proc
	push rax
	push rdi        ; save string pointer
	mov rcx, -1     ; biggest number possible
	xor al, al      ; NUL-Terminator
	repne scasb     ; repeat until reach NUL
	not rcx         ; convert to a positive number
	dec rcx         ; we started from -1
	pop rdi         ; restore string pointer
	pop rax
	ret
str_getlen endp

; Compare ansi/unicode string 
; Input  = RSI -> Address of the src
;          RDI -> Address of the dest
;          RCX -> Number of bytes 
;          R12 -> 0 if the strings are ansi, anything else for unicode
; Output = ZF
str_compare proc
	; Save inputs (The operation will destroy them)
	push rsi
	push rdi
	push rcx
	test r12, r12
	jz cmp_ansi
	repe cmpsw
	jmp cmp_finish
cmp_ansi:
	repe cmpsb
cmp_finish:
	; Restore inputs 
	pop rcx
	pop rdi
	pop rsi
	ret
str_compare endp

; ansi string hashing
; Input  = RSI -> Address of the string
; Output = RAX
str_hash proc
	push rdi                            ; Save dest register
	push rsi                            ; Save sre register
    mov rdi, 5381                       ; DJB2 Magic

compute_hash: ; DJB2 Hashing Algorithm
    xor rax, rax                        ; rax is utilized to reads the string
    lodsb                               ; Fetch a charecter
    cmp al, ah                          ; End of the string!?
    je hash_computed                    ; Don3, go back to the caller
    mov r8, rdi                         ; Save the computed value
    shl rdi, 5                          ; Value << 5
    add rdi, r8                         ; Value += OldValue
    add rdi, rax                        ; Value += ASCII(c)
    jmp compute_hash

hash_computed:
	pop rsi 
	pop rax
	xchg rax, rdi
    ret

str_hash endp

end
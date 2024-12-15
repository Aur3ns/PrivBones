<h1 align="center"> Project PrivBones </h1>

## Table of Contents

1. [Introduction](#introduction)
2. [How Does the Exploit Work?](#how-does-the-exploit-work)
3. [What is an Access Token?](#what-is-an-access-token)
4. [Script Breakdown](#script-breakdown)
5. [Compilation and Usage](#compilation-and-usage)
6. [Prerequisites](#prerequisites)
7. [Legal Disclaimer](#legal-disclaimer)
8. [References](#references)

---

## Introduction

This repository contains a **C-based Proof of Concept (PoC)** script that demonstrates a privilege escalation technique called **Access Token Manipulation**. This technique is widely used in penetration testing and red team operations to elevate privileges and gain SYSTEM-level access on Windows systems.

The script achieves SYSTEM privileges by:
1. Locating a privileged process such as `lsass.exe` or `services.exe`.
2. Stealing its primary access token.
3. Duplicating and assigning the token to the current thread.
4. Spawning a SYSTEM-privileged process, such as `cmd.exe`.

This technique exploits the design of Windows' security model and is a powerful tool when used in authorized environments.

---

## How Does the Exploit Work?

### Key Steps in the Exploit

1. **Enable Privileges:**  
   The script activates critical privileges (`SeDebugPrivilege`, `SeAssignPrimaryTokenPrivilege`, and `SeImpersonatePrivilege`) for the current process. These privileges allow interaction with other processes and token manipulation.

2. **Locate SYSTEM Processes:**  
   Using the `Toolhelp32Snapshot` API, the script enumerates all running processes. It targets processes typically running as SYSTEM, such as `lsass.exe` or `services.exe`.

3. **Verify Security Context:**  
   For each process, the script retrieves the access token and examines the associated **SID (Security Identifier)** to confirm it belongs to the SYSTEM user.

4. **Duplicate and Assign Token:**  
   Once a SYSTEM token is identified, the script duplicates it using `DuplicateTokenEx` and assigns it to the current thread with `SetThreadToken`.

5. **Spawn SYSTEM-Level Process:**  
   Finally, the script uses the duplicated token to start a new process (`cmd.exe`), which runs under the SYSTEM user context.

---

## What is an Access Token?

An **Access Token** is a Windows object that represents the security context of a process or thread. It defines the user's identity, privileges, and security settings.

### Types of Access Tokens:

- **Primary Token:**  
  - Created by the Windows Kernel.  
  - Represents the default security context of a process.  
  - Used when launching a new process.

- **Impersonation Token:**  
  - Captures the security context of a client process.  
  - Used by servers to "impersonate" a client for security operations.

Every process inherits a copy of the access token assigned to the user who started the process. By manipulating these tokens, attackers can alter their security context.

---

## Script Breakdown

### Key Functions in the Script:

1. **`EnablePrivileges()`**
   - Activates specific privileges required for token manipulation.
   - Uses `AdjustTokenPrivileges` to modify the current process token.

2. **`FindSystemProcess()`**
   - Scans all running processes using `Toolhelp32Snapshot` and `Process32Next`.
   - Filters processes like `lsass.exe` or `services.exe` and confirms their SYSTEM ownership by examining their access token with `LookupAccountSid`.

3. **`StealAndImpersonateToken()`**
   - Duplicates the token of a SYSTEM process using `DuplicateTokenEx`.
   - Assigns the duplicated token to the current thread with `SetThreadToken`.

4. **`main()`**
   - Orchestrates the entire process:
     - Enables privileges.
     - Locates a SYSTEM process.
     - Steals and impersonates the SYSTEM token.
     - Spawns a SYSTEM-level command prompt (`cmd.exe`).

---

## Compilation and Usage

### Compilation:

#### Using Microsoft C Compiler (`cl`):
```bash
cl /EHsc /DUNICODE /D_UNICODE privbones.c advapi32.lib
```

#### Using MinGW:
```bash
gcc privbones.c -o privbones.exe -ladvapi32
```

### Usage:

Ensure the script is compiled on a Windows system with the appropriate compiler.
Execute the compiled binary as an administrator:

```bash
privbones.exe
```

If successful, a SYSTEM-privileged command prompt (cmd.exe) will be spawned.

## Prerequisites
**Administrator Privileges**: The current user must have administrator privileges to enable SeDebugPrivilege.


## Legal Disclaimer
This tool is provided for research and educational purposes only. Use it in authorized environments such as penetration testing labs or systems where you have explicit permission from the owner. Unauthorized use of this tool on systems you do not own is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.

## References
 - Microsoft Documentation on Access Tokens
 - Privilege Escalation Techniques - MITRE ATT&CK
 - Understanding Windows Security and Privileges










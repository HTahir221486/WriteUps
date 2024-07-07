```jsx
Machine: Anthem
Platform: TryHackMe
Difficulty: Easy
```
# WALKTHROUGH
You can find the machine [here](https://tryhackme.com/r/room/anthem)

## Recon:

## Task 1:

Starting with the Nmap Vulnerability scanning using the command:

`sudo nmap -sV -sC -Pn --script vuln $IP -vv`

```console
┌──(husnain㉿husnain)-[~]
└─$ sudo nmap -sV -sC -Pn --script vuln 10.10.200.125 -vv
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-07 21:25 PKT
NSE: Loaded 150 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:25
Completed NSE at 21:25, 10.01s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:25
Completed NSE at 21:25, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 21:25
Completed Parallel DNS resolution of 1 host. at 21:25, 0.01s elapsed
Initiating SYN Stealth Scan at 21:25
Scanning 10.10.200.125 [1000 ports]
Discovered open port 3389/tcp on 10.10.200.125
Discovered open port 80/tcp on 10.10.200.125
Completed SYN Stealth Scan at 21:25, 21.61s elapsed (1000 total ports)
Initiating Service scan at 21:25
Scanning 2 services on 10.10.200.125
Completed Service scan at 21:25, 8.57s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.200.125.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:25
NSE Timing: About 96.69% done; ETC: 21:26 (0:00:01 remaining)
NSE Timing: About 97.80% done; ETC: 21:26 (0:00:01 remaining)
NSE Timing: About 98.53% done; ETC: 21:27 (0:00:01 remaining)
NSE Timing: About 98.53% done; ETC: 21:27 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:28 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:28 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:29 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:29 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:30 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:30 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:31 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:31 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:32 (0:00:01 remaining)
NSE Timing: About 99.63% done; ETC: 21:32 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:33 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:33 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:34 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:34 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:35 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:35 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:36 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:36 (0:00:02 remaining)
NSE Timing: About 99.63% done; ETC: 21:37 (0:00:03 remaining)
NSE Timing: About 99.63% done; ETC: 21:37 (0:00:03 remaining)
NSE Timing: About 99.63% done; ETC: 21:38 (0:00:03 remaining)
NSE Timing: About 99.63% done; ETC: 21:38 (0:00:03 remaining)
NSE Timing: About 99.63% done; ETC: 21:39 (0:00:03 remaining)
NSE Timing: About 99.63% done; ETC: 21:39 (0:00:03 remaining)
NSE Timing: About 99.63% done; ETC: 21:40 (0:00:03 remaining)
Completed NSE at 21:40, 871.35s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:40
Completed NSE at 21:40, 11.64s elapsed
Nmap scan report for 10.10.200.125
Host is up, received user-set (0.24s latency).
Scanned at 2024-07-07 21:25:25 PKT for 913s
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 124 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.200.125
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.200.125:80/
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/tags
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/categories
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/search
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/archive/a-cheers-to-our-it-department/
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/archive/we-are-hiring/
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/authors/jane-doe/
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/rss/%7Blink%7D
|     Form id: 
|     Form action: /search
|     
|     Path: http://10.10.200.125:80/authors/jane-doe/THM%7BL0L_WH0_D15%7D
|     Form id: 
|_    Form action: /search
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
| http-enum: 
|   /blog/: Blog
|   /rss/: RSS or Atom feed
|   /robots.txt: Robots file
|   /categories/viewcategory.aspx: MS Sharepoint
|   /categories/allcategories.aspx: MS Sharepoint
|_  /authors/: Potentially interesting folder
3389/tcp open  ms-wbt-server syn-ack ttl 124 Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:40
Completed NSE at 21:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:40
Completed NSE at 21:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 923.65 seconds
           Raw packets sent: 2007 (88.308KB) | Rcvd: 11 (484B)

```

The scan gives answer to the 2nd and 3rd questions. From the scan it is evident that `Port 80` is open which means that there is webpage running. Searching for the IP the following webpage is opened with a domain name `anthem.com`, as shown:

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/83e8381c-8343-4f1d-bf1a-bdcd9cd90405)

***Q. 4: What is a possible password in one of the pages web crawlers check for?***

Analyzing the nmap scan results, a directory `/robots.txt` can be found
```console
| http-enum: 
|   /blog/: Blog
|   /rss/: RSS or Atom feed
|   /robots.txt: Robots file
|   /categories/viewcategory.aspx: MS Sharepoint
|   /categories/allcategories.aspx: MS Sharepoint
|_  /authors/: Potentially interesting folder
3389/tcp open  ms-wbt-server syn-ack ttl 124 Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Accesing the directory through the browser `http://IP/robots.txt`.

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/6287b718-3a49-403c-b2e8-91d972e8fb70)

***Password:***

Password `UmbracoIsTheBest!` can be seen at top of the directory along with other directories. 

***CMS:***

As in the `robots.txt`, the CMS used by the website is `umbraco`.

***Admin:***

Two blogs are written in the website. The 1st blog is written by Jane Doe and the 2nd one is a poem. Searching it on google unveiled the name of the Admin i.e, `Solomon Grundy`.

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/034117ea-aba4-4075-b46a-785b726b61ba)


***Admin Email:***

The 1st blog has the email of its author, the same formate is used to generate the email for the Admin, `SG@anthem.com`.

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/2d15c95b-2d61-4f8c-8d16-6ef3a63a68d9)



## Spoting the Flags:

All of the flags are spotted by looking into the source code of the webpage.

***Flag 1:***

`THM{L0L_WH0_US3S_M3T4}`

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/aec8da53-63da-4d3d-8b10-d6900f0ac416)


***Flag 2:***

`THM{G!T_G00D}`

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/753bd930-2c7c-47b9-8181-038bc2d5e8b7)


***Flag 3:***

Opening the profile of the author of the 1st blog, the flag is spotted there. 

`THM{L0L_WH0_D15}`

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/67834291-899a-4f40-a5b8-c06fa6b95822)


***Flag 4:***

`THM{AN0TH3R_M3TA}`

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/15a38236-3887-4e4e-8555-a2d529a40106)



## Final Stage:

Getting into the box using the gathered information. Accessing the Windows with User SG using remote desktop command, ` rdesktop`, and password, `UmbracoIsTheBest!`, found earlier.
```console
rdesktop $IP
```

There is a file, `user.txt` in the Desktop. It has the **user flag**:

`THM{N00T_NO0T}`

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/69f01b39-d8c2-4197-aa58-04aca62f1b3b)

***Admin Password:***

Changing the view setting to display `hidden file/directories`. A hidden folder, `backup` is displayed. It has `restore.txt` file. Changing the security permission of the txt file to give read and write access to the `SG` user. 

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/92a82832-0407-4307-9c11-684cfe7a4fad)


The password is then revealed.

Admin Password: `ChangeMeBaby1MoreTime`

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/91e62fbd-b538-4d23-abda-3f9e8397fa5e)


***Root Flag:***

Logging as an Administrator using the password, `ChangeMeBaby1MoreTime`.

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/117146d7-af59-43c3-93ec-292a25760648)

After Privilage escalation openning a file, `root.txt` and flag is revealed.

![image](https://github.com/HTahir221486/TryHackMe/assets/132842619/6e5a9136-4b0b-454a-bfd2-bbf9bd74860b)


---

***Try and Crack it*** **; )**

---

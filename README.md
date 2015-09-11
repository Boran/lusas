This is a collection of command line security auditing scripts for Linux/Unix. 

Introduction
============

Auditing the security of an existing Unix system can be time-consuming, and often requires on-site visits. There are several commercial tools and a few free ones that help, but they can be complicated and require local compilation or configuration.

So a tool was developed with the following aims:

* Simple to use: the auditor could even give the tool to the sysadmin, ask him to run it at night and send the results back to the auditor (perhaps by encrypted email).
* For situations where a "quick audit" of the system is required.
* Easy to verify: it is not as thorough as other tools, but it is small and easy to understand.
* Does not require a compiler or other tools.
* Support several Linux and Unix derivatives
* This script automates the gathering of the information only. Of course, the difficult part is the interpretation of results and deciding what countermeasures to take  

The scripts analyse a system but do not make any modifications, with the exception of audit2.pl whiich has one writeable option.

License
=======

These tools are OpenSource. The GPL v2 applies.  

Please share any fixes/improvements you make. Or help with documentation.  Starting Points
https://github.com/boran/lusas/
https://www.pabloendres.com/tools/
http://boran.com/audit


What does it do?
===============

 * lusas-basic.sh: Newer variant of audit1.sh developed by Pablo Enderes.

* audit.sh: Call two main audit scripts: audit1.sh and audit2.pl and collate results.
* remote.sh is an example for running audit.sh on many remote machines via SSH.
* audit1.sh (Bourne shell): This script is designed to run quickly and gather as much security information as possible about the system. lusas-basic.sh is a variant of this one.
No file searches are conducted, to keep it fast.
Tested on: Solaris 2.6/7/8/9, OpenBSD 2.6, RH 7, Suse 7.1/8.1, HP-UX11. Solaris is best supported.

* audit2.pl (perl): This second script searches the entire file system, listing SUID, SGID, world-writable, group-writable files. It also lists trust files and their contents. Finally it lists files with weird names (e.g., containing punctuation characters), which might be danger or a sign of penetration. On a large server with 100GB disks, this can take a few hours to run.
Initially tested on SunOS 5.5/6/7/8/9, OpenBSD 2.6, RH 7, Suse 7.1/8.1/9, HP-UX11.Focus has been on Ubuntu and HP these last few years.

* audit3.sh is a minimal Bourne shell script, that replaces audit2.pl and old systems than don't have Perl. Normally you don't need to run this.
* audit4.sh: Create a list of active tcp/udp connections and listenings in a common format and summarize them in a logfile avoiding very big samplefiles. Udp Sessions cannot be sampled on every architecture.
* audit4_summ.pl: Summarise results from audit4.sh on several machines
* audit5.sh: Create a list of active tcp/udp connections by listening with tcpdump. Collect in a common format and summarize them in a logfile avoiding very big sample files.
* audit5.pl: Create a list of active tcp/udp/icmp connections by listening with tcpdump. Collect in a common format to allow easy viewing in excel Ony record one row for each "connection" (optimise space). WARNING: This script is an optimised version of "audit5.sh", however it seg faults after one hour on one of my test machines, so it can't be considered production ready (SunOS 5.8 Generic_117350-25 sun4u, perl 5.005_03)
* audit5_summ.pl: Summarise results from audit5.sh on several machines. We ignore multiple ICMP & tcp sessions with same from/to IP. UDP: ignore multiple packets to ports 514|53|123 with same from/to IP.
ssh-key-crack: There is a sub directory included ssh-key-crack containing two different tools for analysing the strength of pass phrases used to protect SSH private keys. ssh-privkey-crack.c is more complete than ssh-privkey-crack.c. These tools are include in the auditing bundle since they don't have a site of their own.

USAGE
=====

These scripts are meant for system administrators. Read the headers in each script and checkout the configuration settings at the top of the script. Examples:

./lusas-basic.sh -h
```
OPTIONS:
   -h   Show this message
   -d   email or emails where to send the results. i.e.: a@example.com,b@example.com,root
   -e   Extended.  Collect a copy of files
   -s   Verify package checksums
   -l   Don't clean up after run. Leave the directory with the results on disk.
   -c   Cleanup after run, leave nothing behind.
    If neither -l or -c are not set a .tar.gz file with the result will be left on disk.
```

audit1.sh: 
set EXTENDED='1' for a full audit including extraction of shadow passwords

audit2.pl:
```
# Don't examine these filesystems
$exclude ='/backup|/dir2';     # Don't examine these filesystems
$exclude_dirs='^\/home\/data|^\/home\/stuff';  # do not search these directories
$group_rw = '';                 # '1'=Report group-writeable files (often a huge list we don't care about)
$debug ='';                     # '1'=debug (useful), ''=no debug (quiet)
$debug2='0';                    # '1'=print results to terminal also
                                # (default is to write to file only)
$email_results='0';             # '0'=write to file, don't email
$user='root';                   # send email to him/her
$aggressive = '0';              # '1'=Immediately DELETE baddies
                                # DO NOT DO THIS unless you
                                # have reviewed these sources and tested on a
                                # non-production machine first..
``` 

'sh audit.sh' will call the above two scripts on the local machine.

To run these audit scripts on a number of remote machines via an SSH trust, see the 'remote.sh' example script - adapt it to your needs.
For the other auditing scripts, please read the script headers, they were developed for specific projects and many need tuning for your environment.


todo (2015)
===========
  - move to github, refresh doc..
  - debian/ubuntu support


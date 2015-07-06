# Introduction #

After analiysing the scripts and what they do we decided that we could give a nicer order to the information.


# Details #

**Setup**
  * Setup paths, and variables

**System Info**
  * Hostname
  * Os Info
  * uptime
  * Hw Info
  * Filesystem Info
  * Current runlevel

**User / Accounts Info**
  * w / whodo
  * Accounts checks
  * Passwd and shadow checks
  * Account settings
  * Home directory and SSH trust permissions
  * Sudo
  * Console Security

**Networking Information**
  * Host info
  * Interfaces
  * Interface Statistics
  * Routing
  * Ports and sockets
  * Firewalls

**Kernel, Process, devices, and ports Info**
  * Kernel Info
  * Process Info
  * List open files, devices, ports...
  * Check /dev/random

**Services**
  * Services status
  * Inetd services
  * TCP Wrappers
  * Specific services tests: sendmail, postfix, apache, samba, mysql, postgreSQL, oracle
    * SSH
    * SNMP
    * FTP
    * NTP
    * RPC
    * NFS
    * NIS+
    * X11
    * Samba
    * BIND
    * DHCP
    * LDAP
    * Apache
    * Syslog
    * Cron and at
    * Mail Services
      * Sendmail
      * Postfix
    * Database Servers
      * mysql
      * postgreSQL
      * Oracle
    * Clustering
      * Heartbeat
      * drdb

**Software, Packages**
  * Installed software
  * Patch level
  * List of files with suid and sgid

**Logs**
  * Capture log files
  * Grep for common errors
  * Check for log rotation

**Virtualization**
  * Check for Hypervisers and services
  * Check for Containers and Zones (Solaris)
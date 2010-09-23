#!/bin/sh

# Part of lusas:  linux/unix security auditing scripts
# Licence: GPL v2
# Authors:	Sean Boran <sean AT boran.com>
#		Pablo Endres <epablo AT PabloEndres.com>
# 
# lusas-basic.sh
# Based on the audit1.sh developed by Sean Boran <sean AT boran.com> in 2000
# 


#
# FUNCTION: 
#   Run as root to document the security level of this machine.
#   The idea is to generate a text file for offline analysis.
#   If you run from cron (see below), change the Email address and send
#   either to an email address one hop away, or save to a file and use 
#   a method like scp to get it. Sending it over the Internet is
#   not a good idea... 
#   Tested on OpenBSD, Redhat 7, Suse 7/8/9, HP-UX, Solaris 6-9.
#   Focus is Solaris & Suse Linux 
#   See also the sister script audit2.pl for analysis of file permissions
#   and search for weird files.
#   Set EXTENDED=1 if you want to include password hashes for cracking.
#
# USAGE: 
#  ksh/sh/bash shell:   nice sh ./lusas-basic.sh
# 
#  To follow progress:  tail -f ./lusas-`uname -n`-`date "+%F-%H%M.log"`

#
#  Example cron entry to run on 20th July and mail results:
#    0 0 20 07 * /lusas/lusas-basic.sh 2>&1 |mailx -s "`uname -n` lusas-basic" root
#  Example cron entry for server, large output expected:
#    0 0 20 07 * /lusas/lusas-basic.sh 2>&1 |compress|uuencode \
#     `uname -n`.lusas-basic.sh.Z |mailx -s "`uname -n` lusas-basic" root 
#  On some Linux, replace 'mailx' by 'mail' in the above examples.

VERSION="lusas-basic: 1.1.1";

########## Getopts ###########

usage()
{
cat << EOF
usage: $0 [option]

lusas-basic: 
Linux/unix security auditing scripts.

OPTIONS:
   -h	Show this message
   -d	email or emails where to send the results. i.e.: a@example.com,b@example.com,root
   -e	Extended.  Collect a copy of files
   -s	Verify package checksums
   -l	Don't clean up after run. Leave the directory with the results on disk.
   -c	Cleanup after run, leave nothing behind.

	If neither -l or -c are not set a .tar.gz file with the result will be left on disk.

EOF
}


while getopts ":hd:cles" options; do
  case $options in
    h ) usage
	exit 1;;
    d ) DESTEMAIL=$OPTARG;;
    e ) EXTENDED=1;;
    s ) VERIFY=1;;
    l ) LEAVE=1;;
    c ) CLEANUP=1;;
    \? ) usage
	exit 1;;
    * ) usage
	exit 1;;
  esac
done

##These options exclude each other
if [ $CLEANUP ] && [ $LEAVE ]; then
	echo "-c and -l cannot be used together. \n"
	usage
	exit 1	
fi

##Check for uuencode and warn if it is not there
if [ ! -f /usr/bin/uuencode -o ! -f /bin/uuencode ] && [ $DESTEMAIL ] ; then
	echo "warning:  uuencode is not found on this server, I can't send the results by email"
	echo ""; echo ""
fi

########## Settings ###########
# Debugging
#set -x

# Should /etc/shadow and startup file permissions also be included?
#EXTENDED='0';
#EXTENDED='1';

## What to verify packages
#VERIFY='0';
#VERIFY='1';

########## Globals ###########

## Expression used by egrep to ignore comments
## egrep is not as powerful as perl, and differs a bit between platforms.
comments='^#|^ +#|^$|^ $';
#comments='^#|^    #|^$|^ $';
#comments='^#|^$|^ +$';
f=$0.$$.out

## Output results to screen also?
## These actually have no meaning, I must clean them up.
## in fact all output is to stdout or stderr.
VERBOSE='1';
#VERBOSE_SUM='1';
FILE='0';

###---------- Setup -------

###*Setup*
## DESTDIR: set to define an alternate output dir, default is `pwd`
foldername=lusas-`uname -n`-`date "+%F-%H%M"`
pwd=`pwd`
DESTDIR="$pwd/$foldername"

## Create a dir with the following name lusas-hostname-date
echo "Creating $DESTDIR to store all the results"
mkdir -p $DESTDIR
mkdir -p $DESTDIR/etc
mkdir -p $DESTDIR/etc/sysconfig
mkdir -p $DESTDIR/var
mkdir -p $DESTDIR/var/log

## Save stdout and err just in case
exec 5>&1
exec 6>&2

## Redirect stdout and stderr to logfiles in the directory
logfile="$DESTDIR/lusas-basic.log"
#errlogfile="$DESTDIR/errors.log"
#echo "To followup on progress: tail -f $logfile $errlogfile"
#exec > "$logfile" 2> "$errlogfile"
echo "To followup on progress: tail -f $logfile"
exec >"$logfile" 2>>"$logfile"


## OS name, version and hardware
os=`uname -s`
## We check for SunOS, Linux, HP-UX and OpenBSD
rel=`uname -r`
hw=`uname -m`

##Record the start time to show it at the end
start_time=`date`

#Save $PATH before changing it
ORIG_PATH=$PATH


if [ "$os" = "SunOS" ] ; then
    echo='/usr/5bin/echo'
    ps='ps -ef';
    proc1='/bin/ps -e -o comm ';
    fstab='/etc/vfstab';
    shares='/etc/dfs/dfstab';
    lsof='lsof -i -C';
    mount='mount -p';
    PATH=/bin:/usr/sbin:/usr/ucb:/usr/local/bin:/usr/local/sbin:/opt/csw/sbin:/opt/csw/bin:/opt/sfw/sbin:/opt/sfw/bin:/usr/openwin/bin:/usr/proc/bin:/opt/gnu/bin:/opt/sec/bin:/opt/sec/sbin:/opt/OBSDssh/bin:/opt/openssh/bin:/opt/sec/bin:/opt/postfix:/usr/ccs/bin:/opt/md5
    aliases='/etc/mail/aliases';
    key_progs='/usr/bin/passwd /usr/bin/login /usr/bin/ps /usr/bin/netstat /usr/sbin/modinfo';
    snmp='/etc/snmp/conf/snmpd.conf';
    crontab='crontab -l root';
    ntp='/etc/inet/ntp.conf';
    
elif [ "$os" = "HP-UX" ] ; then
    echo='/usr/bin/echo'
    ps='ps -ef';
  # Proc1 not working on B.11.23
  #proc1='/bin/ps -e -o comm ';
    proc1="ps -e | awk '{print $4}' ";   # get process name, commandline
    fstab='/etc/fstab';
    shares='/etc/exports';
    lsof='lsof -i -C';
    mount='mount -p';
    PATH=/bin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/bin:/usr/local/sbin:/opt/sec/bin:/opt/sec/sbin:/opt/openssh/bin:/usr/local/lsof/bin:/usr/bin/X11:/opt/postfix:/usr/kerberos/bin:/usr/X11R6/bin
    aliases='/etc/mail/aliases';
    key_progs='/usr/bin/passwd /usr/bin/login /usr/bin/ps /usr/bin/netstat';
    snmp='/etc/SnmpAgent.d/snmpd.conf';
    crontab='crontab -l root';
    ntp='/etc/ntp.conf';
    
elif [ "$os" = "Linux" ] ; then
    echo='/bin/echo -e'
    ps='ps -ef';
    proc1='/bin/ps -e -o comm ';
    fstab='/etc/fstab';
    shares='/etc/exports';
    lsof='lsof -i';
    mount='mount';
    PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:/usr/lib/saint/bin:/opt/postfix:/usr/lib/java/jre/bin
    aliases='/etc/aliases';
    key_progs='/usr/bin/passwd /bin/login /bin/ps /bin/netstat';
    snmp='/etc/snmp/snmpd.conf';
    crontab='crontab -u root -l';
    ntp='/etc/ntp.conf';
    
	## Find out which distribution we are using
    if [ -f  /etc/redhat-release ] ; then
	dist="redhat"
    elif [ -f  /etc/redhat-release ] ; then
	dist="suse"
    elif [ -f  /etc/lsb-release ] ; then
		##Debian and derivates (Ubuntu)
	dist="debian"
    else
	dist=""
    fi
    
elif [ "$os" = "OpenBSD" ] ; then
    echo='/bin/echo'
    ps='ps -auwx';
    proc1='/bin/ps -e -o comm ';
    fstab='/etc/fstab';
    shares='/etc/exports';
    lsof='lsof -i';
    mount='mount';
    PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin
    aliases='/etc/aliases';
    key_progs='/bin/passwd /bin/login /bin/ps /bin/netstat';
    snmp='/etc/snmp/snmpd.conf';
    crontab='crontab -l root';
    ntp='/etc/inet/ntp.conf';
    
fi

## common programs
sum='/usr/bin/sum';
##Todo: Test to findout where a program is intalled
## Checksum programs preference order: sha1sum, md5sum, sum

if [ -f /opt/sfw/bin/sha1sum ] ; then
	## Solaris
    md5sum="/opt/sfw/bin/sha1sum"
elif [ -f /usr/bin/sha1sum ] ; then
	## Linux
    md5sum="/usr/bin/sha1sum"
else 
	##Didn't find it
    md5sum="/bin/false"
fi

###---------- End Setup -------

###---------- Functions -------

check_err () {
    if [ "$*" != "0" ] ; then
	$echo "SCRIPT $0 ABORTED: error." >>$f 2>&1
	send_results;
	exit 1;
    fi
}
run () {
    if [ $FILE = "1" ]    ; then $echo "Running command: $*" >>$f;   fi
    if [ $VERBOSE = "1" ] ; then $echo "Running command: $*";        fi
    if [ $FILE = "1" ]    ; then $*    >> $f;
    else
	$*;
    fi
}

#doc () {
#  if [ $FILE = "1" ]    ; then $echo "$*";     >> $f;  fi
#  if [ $VERBOSE_SUM = "1" ] ; then $echo "$*";         fi
#}

###---------- End Functions ---case ----

###---------- Main -------

$echo ">>>>>>>>>> AUDIT SCRIPT: $0 $VERSION <<<<<<<<<<<"
date
$echo ""
$echo ""


###*System Info*
$echo ">>>>>>>>>> System Info ----------"
###  * Hostname
$echo "hostname: `/bin/hostname`"
$echo ""

###  * Os Info
$echo "---------- OS Info ----------"
# What OS release are we running?
run uname -a
$echo ""
$echo "This is a $os $rel on $hw"
os=`uname -s`

$echo ""
$echo "Release Info:"
$echo ""
if   [ "$os" = "Linux" ] ; then 
    cat /etc/lsb-release 2>/dev/null
    cat /etc/redhat-release  2>/dev/null
    cat /etc/SuSE-release 2>/dev/null
elif   [ "$os" = "SunOS" ] ; then
    cat /etc/release 2>/dev/null
fi

###  * uptime
$echo ""
run uptime

###  * Hw Info
$echo ""
$echo "---------- Hardware Info ----------"
if   [ "$os" = "Linux" ] ; then 
    
    $echo "=======Bios========================"
    /usr/sbin/dmidecode --type 0
    $echo ""
    $echo "=======CPU Info========================"
    /bin/cat /proc/cpuinfo |/bin/grep -E "processor|model name"
    $echo ""
    $echo "=======Memory Info========================"
    /usr/sbin/dmidecode --type 6 |/bin/grep -E "Socket|Type|Installed"
    $echo ""
    run /usr/bin/free -m
    $echo "=========================================="
    $echo ""
    $echo "For more Hw information run lspci, lsdev and lsusb"
    $echo "\n\n"
    
	## Is SuSE siga installed? We can list the entire system HW/SW config
    if [ "$dist" = "suse" ]  ; then
	$echo " =======Suse Siga========================"
	siga 2>/dev/null
	cat < /tmp/siga/siga.txt 2>/dev/null
    fi
    
elif   [ "$os" = "SunOS" ] ; then
    run /usr/sbin/prtdiag
    $echo "\n\n=======Eeprom Settings========================"
    /usr/sbin/eeprom -v | egrep "boot|security"
    $echo ""
    $echo "Checking swap:"
    run swap -l
    $echo "\n\n"
    
elif   [ "$os" = "HP-UX" ] ; then
    /bin/false ##Place holder
elif   [ "$os" = "OpenBSD" ] ; then
    /bin/false ##Place holder
fi

###  * Filesystem Info
$echo "---------- Filesystem Info ----------\n"
##Comments
##Todo: Should we leave these comments?
#$echo     "          Are any disks nearly full, are partitions well allocated?"
#$echo     "          Are options like ro,logging,nosuid,size used?"
#$echo ""

if   [ "$os" = "Linux" ] || [ "$rel" = "5.10" ] ; then 
    run /bin/df -h
else 
    run /bin/df -k
fi
$echo ""
run mount
$echo ""

###  * Current runlevel
$echo "---------- Current runlevel ----------\n"
run who -r
$echo ""

###*User / Accounts Info*
$echo ">>>>>>>>>> User / Accounts Info ----------"
###  * w / whodo
$echo "---------- w / whodo ----------\n"
$echo "Logged on users:"
w

if   [ "$os" = "SunOS" ] ; then 
    $echo "\nwhodo: "
    run whodo
    $echo ""
fi

###  * Accounts checks
$echo "\n---------- Accounts checks ----------\n"
$echo "Account, password and shadow checks"
$echo "Number of accounts: `wc -l /etc/passwd`"

$echo "\nAccounts with UID=0: " 
$echo `awk -F: '{if ($3=="0") print $1}' /etc/passwd`

$echo "\nNIS(+)/YP accounts: " 
grep '^+' /etc/passwd /etc/group
ypcat passwd 2>/dev/null
niscat passwd 2>/dev/null


$echo "\nAccounts with no password:"
if   [ "$os" = "SunOS" ] ; then 
    run logins -p -x
elif [ "$os" = "HP-UX" ] ; then
    run logins -p -x
else 
    if [ -f /etc/shadow ] ; then
	$echo `awk -F: '{if ($2=="") print $1}' /etc/shadow`
    else
	$echo `awk -F: '{if ($2=="") print $1}' /etc/passwd`
    fi
fi      

$echo "\nAccounts with passwords (not blocked or empty)"
if   [ "$os" != "HP-UX" ] ; then
    $echo `awk -F: '{if (($2!="*") && ($2!="") && ($2!="!") && ($2!="!!") && ($2!="NP") && ($2!="*LK*")) print $1}' /etc/shadow`
else
    $echo "\nAccounts with passwords (not blocked or empty)"
    $echo `awk -F: '{if (($2!="*") && ($2!="") && ($2!="!") && ($2!="!!") && ($2!="NP") && ($2!="*LK*")) print $1}' /etc/passwd`
fi

##Perl One liner to find users with duplicated uids
##http://linuxgazette.net/issue85/okopnik.html
##Todo: Check for perl at the begining and / or find a better way to do this
if [ "$os" != "HP-UX" ] && [ "$os" != "SunOS" ] ; then
    if [ -f /usr/bin/perl ] ; then
	$echo "\nDuplicate Accounts"
	/usr/bin/perl -F: -walne'$h{$F[2]}.="$F[0] ";END{$h{$_}=~/ ./&&print"$_: $h{$_}"for keys%h}' /etc/passwd
    fi
elif   [ "$os" = "HP-UX" ] ; then
    $echo "\nDuplicate Accounts"
    run logins -d -x -m
    
elif   [ "$os" = "SunOS" ] ; then
    $echo "\nDuplicate Accounts"
    run logins -d -x -m
    
fi

#+ Passwd and shadow checks
$echo "\nPassword settings:"
if   [ "$os" = "SunOS" ] ; then 
    $echo " /etc/default/passwd settings: "
    egrep -v "$comments" /etc/default/passwd
    $echo "\n  nsswitch.conf:"
    $echo "nsswitch.conf: `egrep '^passwd' /etc/nsswitch.conf`"
    $echo "nsswitch.conf: `egrep '^group' /etc/nsswitch.conf`"
    $echo "nsswitch.conf: `egrep '^hosts' /etc/nsswitch.conf`"
    $echo "nsswitch.conf: `egrep '^netgroup' /etc/nsswitch.conf`"
    $echo "\nCheck dormant/invalid accounts /expiry dates: 'passwd -sa'"
    run passwd -sa
    
elif [ "$os" = "OpenBSD" ] ; then 
    $echo "/etc/passwd.conf :"
    egrep -v "$comments" /etc/passwd.conf
    
elif [ "$os" = "HP-UX" ] ; then 
    $echo "/etc/pam.conf :"
    egrep -v "$comments" /etc/pam.conf
    
else
    $echo "/etc/pam.d/passwd :"
    egrep -v "$comments" /etc/pam.d/passwd
    $echo "\n/etc/pam.d/system-auth :"
    egrep -v "$comments" /etc/pam.d/system-auth
fi

if   [ "$os" = "Linux" ] ; then 
    $echo "\nChecking for dormant/invalid with: pwck -r"
    pwck -r
    $echo "\n and grpck -r"
    grpck -r
fi

if [ "$EXTENDED" = "1" ] ; then 
    cp -p /etc/passwd $DESTDIR/etc/
    cp -p /etc/shadow $DESTDIR/etc/
    mkdir -p $DESTDIR/etc/ssh/
    cp -p /etc/ssh/ssh* $DESTDIR/etc/ssh/
fi

###    * Account settings
$echo "\n\n"
$echo "---------- Account settings ----------\n"
$echo "\nEnvironment variables and PATH:"
$echo "(check especially for '.' in the root PATH)"
env
echo $ORIG_PATH
$echo "\nroot interactive umask (should be at least 022, or better 027 or 077):"
umask
$echo "\nSearching for Daemon umasks in /sbin/init.d/*/* (to see if daemons start securely):"
egrep -v "$comments" /sbin/init.d/*  2>/dev/null | grep umask
egrep -v "$comments" /sbin/init.d/*/* 2>/dev/null | grep umask
egrep -v "$comments" /etc/init.d/*   2>/dev/null | grep umask
egrep -v "$comments" /etc/init.d/*/* 2>/dev/null | grep umask
if [ "$os" = "SunOS" ] ; then
    $echo "\nDefault system umask. Contents of /etc/default/init:"
    egrep -v "$comments" /etc/default/init
fi

$echo "\nHome directory and SSH trust permissions: (watch out for world/group writeable)"
#awk -F: '{print $6}' /etc/passwd | uniq| xargs ls -ld 2>/dev/null
for h in `awk -F: '{print $6}' /etc/passwd | uniq` ; do
    # Check permissions of ~/, ssh pub-key auth and rhosts
    ls -ald $h
    for i in $h/.ssh/authorized_keys $h/.ssh/authorization $h/.rhost; do
      # Check for the files and their contents
      if [ -f $i ] ; then
	  ls -ald $i
	  $echo "$i:"
	  cat $i
      fi
    done
    $echo ""
done

$echo "\n/etc/shells:"
egrep -v "$comments" /etc/shells    2>/dev/null

$echo "\nsudo: /etc/sudoers:"
egrep -v "$comments" /etc/sudoers 2>/dev/null

$echo "\nConsole security:"
if     [ "$os" = "HP-UX" ] ; then 
    $echo "root is allowed to logon to the following (/etc/securetty) -"
    egrep -v "$comments" /etc/securetty 2>/dev/null
    
elif   [ "$os" = "SunOS" ] ; then 
    $echo "/etc/default/login :"
    egrep -v "$comments" /etc/default/login
    
    
elif   [ "$os" = "Linux" ] ; then 
    $echo "root is allowed to logon to the following (/etc/securetty) -"
    egrep -v "$comments" /etc/securetty 2>/dev/null
    grep securetty /etc/pam.d/login 2>/dev/null
    grep ROOT_LOGIN_REMOTE /etc/rc.config 2>/dev/null
fi


###*Networking Information*
$echo "\n\n"
$echo ">>>>>>>>>> Networking Information ----------"

###  * Host info
$echo "---------- Host info ----------\n"

$echo "\n/etc/nsswitch.conf - hosts entry:"
grep hosts /etc/nsswitch.conf 
$echo "\n/etc/resolv.conf :"
egrep -v "$comments" /etc/resolv.conf
$echo "\n/etc/hosts :"
egrep -v "$comments" /etc/hosts
$echo ""; $echo ""

###  * Interfaces
$echo "\n---------- Interfaces ----------\n"
#$echo "Interfaces:"
if   [ "$os" = "HP-UX" ] ; then 
    lanscan
    ifconfig lan0;
    ifconfig lan1 2>/dev/null;
else
    ifconfig -a;
fi

###  * Interface Statistics
$echo "\n---------- Interface Statistics ----------\n"

netstat -in;

###  * Routing
$echo "\n---------- Routing ----------\n"

netstat -rn;

###  * Ports and sockets
$echo "\n---------- Ports and sockets ----------\n"
#$echo "\nNetwork connections - current:"

if [ "$os" = "Linux" ] ; then
  netstat -atpn
  netstat -aupn

elif [ "$os" = "SunOS" ] ; then
  #netstat -an -P tcp
  #netstat -an -P udp
  netstat -an -f inet
  netstat -an -f inet6

  #$echo "\nls -l /proc (You only need to look at this if an intrusion is probable)"
  $echo "\nProcesses, and socks, from 'pfiles /proc/*"
  pfiles /proc/* | egrep 'sockname: AF_INET|peername|^[0-9]+:'| egrep -v 'sockname: AF_INET 0.0.0.0'

else
  netstat -an
fi

###  * List open files, devices, ports... 
$echo "\n---------- List open files, devices, ports ----------\n"
##Todo: Should these comments be here?
#$echo "\n\n>>>>> Is lsof installed? We can list open files, device, ports ---"
which lsof 2>/dev/null
$lsof;
##Todo: Check lsof parameters for sol 10
#/opt/csw/bin/lsof: illegal option character: C


###  * Firewalls
$echo "\n---------- Firewalls ----------\n"

##Todo: Should these files be moved to the results dir?
$echo "Local firewall configuration:\n" 
if   [ "$os" = "Linux" ] ; then 
    if  [ -f  /sbin/iptables ] ; then
		## iptables kernel +2.4
	run /sbin/iptables -L -vn
		## show the static script
		##Redhat
	$echo "\n  /etc/sysconfig/iptables:"
	egrep -v "$comments" /etc/sysconfig/iptables 2> /dev/null
	$echo "\n  /etc/sysconfig/iptables-config:"
	egrep -v "$comments" /etc/sysconfig/iptables-config 2> /dev/null

	if [ "$EXTENDED" = "1" ] && [ "$dist" =  "redhat"  ]  ; then 
    		cp -p /etc/sysconfig/iptables $DESTDIR/etc/sysconfig/
   		cp -p /etc/sysconfig/iptables-config $DESTDIR/etc/sysconfig/
	fi
	
    elif [ -f  /sbin/ipchains ] ; then
		# ipchains kernel 2.0 - 2.2
	run /sbin/ipchains -L -vn
    fi
    
elif   [ "$os" = "SunOS" ] ; then
	#ipf
    if [ -f /usr/sbin/ipfstat ] ; then
	$echo ""
	run /usr/sbin/ipfstat -i
	run /usr/sbin/ipfstat -o
	run /usr/sbin/ipfstat
    fi
    
	## Detect Sun's Sunscreen Firewall
    if   [ "$os" = "SunOS" ] && [ -f  /opt/SUNWicg/SunScreen/bin/ssadm ]; then
	policy=`$ssadm active 2>/dev/null|grep Active|awk '{print $5}'| sed 's/\.[0-9]*//g' `
	[ $? = 0 ] && $ssadm edit $policy -c "list rule";
    fi
    
elif   [ "$os" = "HP-UX" ] ; then
    /bin/false ## Place holder
##Todo: HP-UX firewall
elif   [ "$os" = "OpenBSD" ] ; then
##Todo: OpenBSD firewall
    /bin/false ## Place holder
fi


###*Kernel, Process, devices, and ports Info*
## Send this section to it's own file
exec >"$DESTDIR/kernel" 2>>"$DESTDIR/kernel"
$echo "\n\n== Running kernel, process, device and ports Module ==" >> "$logfile"
$echo "Look for details in: $DESTDIR/kernel" >> "$logfile"

$echo "\n\n"
$echo ">>>>>>>>>> Kernel, Process, devices, and ports Info ----------"

###  * Kernel Info
$echo "---------- Kernel Info ----------\n"

if   [ "$os" = "Linux" ] ; then 
    $echo "\nLinux security settings:"
    files="/etc/security/* /etc/rc.config"
    for f in $files ; do
	if [ -f $f ] ; then 
	    $echo "\nLinux Security config... $f .."
	    egrep -v "$comments" $f
	fi
    done;
    
    $echo "\nLinux: kernel parameters --"
    for f in net.ipv4.ip_forward net.ipv4.conf.all.forwarding net.ipv4.conf.all.mc_forwarding net.ipv4.conf.all.rp_filter net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_echo_ignore_all net.ipv4.tcp_max_syn_backlog  /proc/sys/net/ipv4/tcp_syncookies net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.send_redirects   net.ipv4.ip_always_defrag net.ipv4.conf.all.log_martians  net.ipv4.tcp_syn_retries ; do
	
     #echo `sysctl $f` 2>/dev/null
	sysctl $f 2>/dev/null
    done
    $echo ""
    $echo "cat /proc/sys/net/ipv4/conf/*/log_martians"
    cat /proc/sys/net/ipv4/conf/*/log_martians
    $echo ""
    
    if [ "$EXTENDED" = "1" ] ; then
	$echo "\nLinux: kernel modules (modprobe -c -l) --\n"
	##Todo: Linux Kernel Modules - Why are we doing this?
	#run modprobe -c -l
	## List active modules
	run lsmod
    fi
    
fi

if   [ "$os" = "HP-UX" ] ; then 
    $echo "\nHP-UX /stand/system contents--"
    egrep -v '^\*|^$' /stand/system
    
    $echo "\nHP-UX  ndd parameters --"
    
    $echo "\narp_cleanup_interval (should be ~6000)=`ndd /dev/arp arp_cleanup_interval`"
    $echo "\nudp_def_ttl (should be ~128)=`ndd /dev/arp udp_def_ttl`"
    
  $echo "\ntcp values - Desired values : tcp_keepalive_interval=3600000 tcp_keepalive_detached_interval=60000 tcp_time_wait_interval=30000 tcp_syn_rcvd_max=500 tcp_conn_req_max=256 tcp_text_in_resets=0"
  $echo "tcp values - actual values : "
  for f in tcp_keepalive_interval tcp_keepalive_detached_interval tcp_time_wait_interval tcp_syn_rcvd_max tcp_conn_req_max tcp_text_in_resets ; do
    echo "$f=`ndd /dev/tcp  $f`"
  done
  
  $echo "\nndd - desired values :  ip_forwarding=0 ip_forward_src_routed=0 ip_forward_directed_broadcasts=0 ip_ire_gw_probe=0 ip_check_subnet_addr=0 ip_ire_gw_probe_interval=18000 ip_respond_to_echo_broadcast=0 ip_respond_to_timestamp=0 ip_respond_to_timestamp_broadcast=0 ip_send_redirects=0 ip_send_source_quench=0 "
  $echo "ip values - actual values : "
  for f in ip_forwarding ip_forward_src_routed ip_forward_directed_broadcasts ip_ire_gw_probe ip_check_subnet_addr ip_ire_gw_probe_interval ip_respond_to_echo_broadcast ip_respond_to_timestamp ip_respond_to_timestamp_broadcast ip_send_redirects ip_send_source_quench    ip_respond_to_address_mask_broadcast ip_ire_flush_interval ip_strict_dst_multihoming ip_pmtu_strategy ; do
    echo "$f=`ndd /dev/ip  $f`"
  done
  
fi

if   [ "$os" = "SunOS" ] ; then 
  $echo "Sun: strong ISS tcp sequences?--"
  egrep -v "$comments" /etc/default/inetinit 

  $echo "\n\nSun: /etc/system contents--"
  egrep -v '^\*|^$' /etc/system

  $echo "\n\nSun: ndd parameters --"
  echo "arp_cleanup_interval=`ndd /dev/arp arp_cleanup_interval`"

  ## UDP
  for f in udp_extra_priv_ports; do
    echo "$f=`ndd /dev/udp  $f`"
  done

  ## TCP
  for f in tcp_strong_iss tcp_conn_req_max_q tcp_conn_req_max_q0 tcp_extra_priv_ports tcp_time_wait_interval tcp_ip_abort_cinterval; do
    echo "$f=`ndd /dev/tcp  $f`"
  done
  $echo "\nndd TCP desired values: tcp_ip_abort_cinterval=60000 (1min) to mitigate SYN flooding. For Solaris <2.6 check also  tcp_conn_req_max."
  $echo " "
  ## IP
  $echo "\nndd IP desired values: ip_forwarding=0 ip_forward_src_routed=0 ip_forward_directed_broadcasts=0 ip_check_subnet_addr=0 ip_respond_to_echo_broadcast=0 ip_respond_to_timestamp=0 ip_respond_to_timestamp_broadcast=0 ip_send_redirects=0 ip_send_source_quench=0 "
  $echo "\nndd ip - actual values : "
  for f in ip_forwarding ip_strict_dst_multihoming ip_respond_to_echo_broadcast ip_forward_directed_broadcasts tcp_rev_src_routes ip_respond_to_timestamp ip_respond_to_address_mask_broadcast ip_ignore_redirect ip_ire_flush_interval ip_forward_src_routed ip_send_redirects ip6_forwarding ip6_send_redirects ip6_ignore_redirect; do
    echo "$f=`ndd /dev/ip  $f`"
  done

  $echo "\n\nSun: kernel modules loaded (modinfo) --"
  $echo   "          If you suspect a penetration, check for root kit modules."
  /usr/sbin/modinfo

fi

###  * Process Info
## Returning output to the main logfile
#exec >>"$logfile" 2>>"$logfile"
$echo "\n---------- Process Info ----------\n"

##Todo: Should these comments be here?
#$echo "\n\n>>>>> Processes "
#$echo     "      Are any unexpected processes running, are too many running"
#$echo     "      as root?"
run $ps



###  * Check /dev/random
$echo "\---------- Check /dev/random ----------\n"
ls -l /dev/random 2>/dev/null

###*Services*
$echo "\n\n== Running Services Module ==" >> "$logfile"
$echo "Look for details in: $DESTDIR/services" >> "$logfile"

## Send this section to it's own file
exec >"$DESTDIR/services" 2>>"$DESTDIR/services"
$echo "Running Services Module" >> "$logfile"

$echo ">>>>>>>>>> Services ----------"

##Todo: Most of this section should be writting to it's own subdirectory to maintain the audit readable


###  * Services status
$echo "---------- Services status ----------\n"

if   [ "$os" = "Linux" ] ; then 

##Todo: Finish linux service list
	if [ "$dist" =  "redhat" ] ; then
		$echo "Running services -----\n"
		for i in `ls /etc/init.d/xinetd CHANGES`; do 
		  # Verify that the script checks $1
		  grep case $i|grep \$1 >/dev/null 2>&1
		  if [ $? = 0 ]; then
		    $i status
		  fi
		done
		$echo ""		
		$echo "Services boot config -----\n"
		run chkconfig --list

	elif [ "$dist" =  "suse" ] ; then
		/bin/false ## place holder

	elif [ "$dist" =  "debian" ] ; then
		##Debian and derivates (Ubuntu)
		/bin/false ## place holder
	fi

elif   [ "$os" = "SunOS" ] ; then
	if [ "$rel" = "5.10" ] ; then
		$echo "Running services -----"
		svcs
	else
		for i in `ls /etc/init.d/xinetd CHANGES`; do 
		  # Verify that the script checks $1
		  grep case $i|grep \$1 >/dev/null 2>&1
		  if [ $? = 0 ]; then
		    $i status
		  fi
		done
		$echo ""	
	fi

elif   [ "$os" = "HP-UX" ] ; then
	##Todo: 
	/bin/false ## place holder
elif   [ "$os" = "OpenBSD" ] ; then
	##Todo: 
	/bin/false ## place holder
fi

###  * Inetd services
$echo "\n---------- Inetd services ----------\n"

echo "\nChecking for inetd process.."
$ps | grep inetd
if [ -f /etc/inetd.conf ] ; then
  echo "\nChecking /etc/inetd.conf.."
  egrep -v "$comments" /etc/inetd.conf
fi;
if [ -f /etc/xinetd.conf ] ; then
  echo "\nChecking /etc/xinetd.conf.."
  egrep -v "$comments" /etc/xinetd.conf
  ls -l /etc/xinetd.d
  echo "\nChecking for enabled services in xinetd.."
  egrep "disable.*no"  /etc/xinetd.d/*
fi;

###  * TCP Wrappers
$echo "\n---------- TCP Wrappers ----------\n"
$echo "\nTCP Wrappers, /etc/hosts.allow: "
egrep -v "$comments" /etc/hosts.allow   2>/dev/null
$echo "\t/etc/hosts.deny: "
egrep -v "$comments" /etc/hosts.deny    2>/dev/null


###  * Specific services tests: sendmail, postfix, apache, samba, mysql, postgreSQL, oracle
$echo "\n---------- Specific services tests ----------\n"
###    * SSH
$echo "---------- SSH ----------\n"
# SSH daemon version
$ps | grep sshd

$echo "\ndeamon version:"
process=`${proc1} | sort | uniq | grep sshd`
[ $? = 0 ] && $process -invalid 2>&1|head -2|tail -1;
# SSH client version
$echo "\nclient version:"
ssh -V 2>&1

$echo "\nWhere:"
run whereis ssh


$echo "\nActive SSHD config:"
files="/etc /etc/ssh /usr/local/etc /opt/openssh/etc /opt/ssh/etc"
for f in $files ; do
  if [ -f $f/sshd_config ] ; then 
    echo "ssh config: $f/sshd_config .."
    egrep -v "$comments" $f/sshd_config
  fi
done;
$echo ""

###    * SNMP
$echo "---------- SNMP ----------\n"
#$echo "\n\n>>>>> SNMP , config $snmp ------" 
$echo "SNMP , config $snmp \n" 
if [ -f $snmp ] ; then 
  egrep -v "$comments" $snmp
fi
$echo "\nIs the deamon running"
$ps | grep snmp


###    * FTP
$echo "\n---------- FTP ----------\n"

$echo "\n/etc/ftpusers:"
egrep -v "$comments" /etc/ftpusers  2>/dev/null
$echo "\nvsftpd.conf:"
egrep -v "$comments" /etc/vsftpd.conf  2>/dev/null
egrep -v "$comments" /etc/vsftpd/vsftpd.conf  2>/dev/null
if [ -f /etc/vsftpd.chroot_list ] ; then
  cat /etc/vsftpd.chroot_list
fi

$echo "\nInetd.conf contents relevant to FTP:"
if [ -f /etc/inetd.conf ] ; then
  egrep ftpd /etc/inetd.conf 
fi
if [ -f /etc/xinetd.conf ] ; then
  echo "Checking /etc/xinetd.d/*ftp*:"
  ls -l /etc/xinetd.d/*ftp*
  cat /etc/xinetd.d/*ftp*
fi;

###    * NTP
$echo "\n---------- NTP ----------\n"

$ps | grep ntpd
$echo "\nntp config - $ntp:"
egrep -v "$comments" $ntp 2>/dev/null
$echo ""
run ntpq -p


###    * RPC
$echo "\n---------- RPC ----------\n"

rpcinfo -p localhost  2>/dev/null

###    * NFS
$echo "\n---------- NFS ----------\n"
$echo "\n NFS sharing:"
egrep -v "$comments" $shares 2>/dev/null
showmount -e          2>/dev/null
showmount -a          2>/dev/null

$echo "\n NFS client:"
egrep -v "$comments" $fstab | grep nfs
$mount | grep nfs


###    * NIS+
$echo "\n---------- NIS+ ----------\n"
nisls -l 2>/dev/null

###    * X11
$echo "\n---------- X11 ----------\n"
##Todo: Check if X server is running

$echo "\nX11 - xauth"  
echo "DISPLAY = `echo $DISPLAY`"
xauth list
# xhost blocks sometime (when X11 running and no display?)
#xhost
echo "ls /etc/X*.hosts : `ls /etc/X*.hosts 2>/dev/null`"


###    * Samba
$echo "\n---------- Samba ----------\n"

$echo "deamon info:"
$ps | grep smbd | egrep -v "grep smbd"

##Todo: The next line does not work on HP-ux "audit1.sh[780]: 3833:  not found"
process=`${proc1} | sort | uniq | grep smbd`
[ $? = 0 ] && echo "Samba `$process -V`";

##Todo: smb Even though it's not running it's not a bad idea to check for it
##If there recommend to uninstall when not being used

files="/var/log/samba /var/log.smb /var/log/log.smb"
for f in $files ; do
  if [ -f $f ] ; then 
    $echo "\nsamba logs $f:"
    ls -l $f
  fi
done;

files="/usr/local/samba/lib/smb.conf /etc/samba/smb.conf"
for f in $files ; do
  if [ -f $f ] ; then 
    $echo "\nsamba config $f .."
    # Samba can have comments with ';'
    egrep -v "$comments" $f | egrep -v "^;"
  fi
done;

###    * BIND
$echo "\n---------- BIND ----------\n"

$ps | grep dnsmasq | egrep -v "grep dnsmasq"
process=`${proc1} | sort | uniq | grep dnsmasq`
[ $? = 0 ] && $process -v 2>&1;

$ps | grep named | egrep -v "grep named"
process=`${proc1} | sort | uniq | grep named`
[ $? = 0 ] && $process -v;

for f in `whereis named| awk -F: '{print $2}'` ; do ls -l $f;  done;

files="/etc/named.conf /usr/local/etc/named.conf /etc/dnsmasq.conf"
for f in $files ; do
  if [ -f $f ] ; then 
    $echo "\nDNS config... $f .."
    egrep -v "$comments|^//|^/\*|^ \*" $f
  fi
done;


###    * DHCP
$echo "\n---------- DHCP ----------\n"

$ps | grep dhcpd| egrep -v "grep dhcpd"
for f in `whereis dhcpd| awk -F: '{print $2}'` ; do ls -l $f;  done;
# Version
process=`${proc1} | sort | uniq | grep dhcpd`
[ $? = 0 ] && $process -V 2>&1|head -1;

files="/etc /opt/ISC_DHCP /etc /etc/dhcpd"
for f in $files ; do
  if [ -f $f/dhcpd.conf ] ; then 
    $echo "\ndhcp config... $f .."
    egrep -v "$comments" $f/dhcpd.conf
  fi
done

###    * LDAP
$echo "\n---------- LDAP ----------\n"

$ps | grep slapd| egrep -v "grep slapd"
for f in `whereis slapd| awk -F: '{print $2}'` ; do ls -l $f;  done;
# Version
#process=`${proc1} | sort | uniq | grep slapd`
#[ $? = 0 ] && $process -v;

files="/var/log/openldap/logfile"
for f in $files ; do
  if [ -f $f ] ; then 
    #$echo "\nhttpd logs... $f .."
    run tail -50 $f
  fi
done;

files="/opt/openldap/etc"
for f in $files ; do
  if [ -d $f ] ; then 
    $echo "\nLDAP config dir... $f .."
  fi
done;

###    * Apache
$echo "\n---------- Apache ----------\n"

$echo "https Procesess:"
$ps | grep httpsd| egrep -v "grep httpsd"
$echo "\nhttps file permissions:"
for f in `whereis httpsd| awk -F: '{print $2}'` ; do ls -l $f;  done;
# Version http with SSL
process=`${proc1} | sort | uniq | grep httpsd`
[ $? = 0 ] && $process -v;

$echo "http Procesess:"
$ps | grep httpd| egrep -v "grep httpd"
$echo "\nhttp file permissions:"
for f in `whereis httpd| awk -F: '{print $2}'` ; do ls -l $f;  done;

# Version httpd
$echo "\nhttpd version:"
process=`${proc1} | sort | uniq | grep httpd`
[ $? = 0 ] && $process -v;

## Apache: config 
## List of directory where apache is normally installed
dirs="/etc/httpd/conf /etc/httpd/conf.d /etc/apache /etc/apache2 /usr/local/apache/conf /usr/local/apache2/conf /opt/apache/conf var/www/conf /opt/portal/apache/conf"
for d in $dirs; do
  if [ -d $d ] ; then
    files=`find $d -name "*.conf"`
    for f in $files ; do
      $echo "\nhttpd config ... $f .."
      egrep -v "$comments" $f
      $echo ""
    done
  fi
done
    
## Apache: error logs
files="/usr/local/apache /usr/local/apache2 /opt/apache /var/www /opt/portal/apache /var/log/httpd/"
for f in $files/logs/error_log ; do
  if [ -f $f ] ; then 
    #$echo "\nhttpd logs... $f .."
    run tail -50 $f
  fi
done;
files="/var/log/httpd/error_log /var/log/apache2/error_log /var/log/apache/httpsd_error_log /var/log/apache/httpd_error_log"
for f in $files ; do
  if [ -f $f ] ; then 
    #$echo "\nhttpd logs... $f .."
    run tail -50 $f
  fi
done;

files="/usr/local/apache /usr/local/httpd /usr/local/apache2 /opt/apache /var/www /opt/portal/apache /srv/www "
for f in $files; do
  if [ -d $f/cgi-bin ] ; then 
    $echo "\ncgi scripts in $f/cgi-bin .."
    ls -al $f/cgi-bin
  fi
done;

###    * Syslog
$echo "\n---------- Syslog ----------\n"

$echo "loghost alias in /etc/hosts:"
grep loghost /etc/hosts
$echo "\nChecking /etc/syslog.conf .."
egrep  -v "$comments" /etc/syslog.conf      2>/dev/null
$echo "\nChecking /etc/syslog-ng.conf .."
egrep  -v "$comments" /etc/syslog-ng.conf      2>/dev/null
egrep  -v "$comments" /etc/syslog-ng/syslog-ng.conf      2>/dev/null
egrep  -v "$comments" /usr/local/etc/syslog-ng.conf      2>/dev/null
$echo "\nChecking /etc/rsyslog.conf .."
egrep  -v "$comments" /etc/rsyslog.conf      2>/dev/null

###    * Cron
$echo "\n---------- Cron ----------\n"

$echo "root cron:"
$crontab | egrep -v "$comments"
egrep -v "$comments" /etc/crontab 2>/dev/null
$echo ""

if   [ "$os" = "SunOS" ] ; then 
  $echo "\n/etc/cron.d/ :"
  ls -l /etc/cron.d/
  cat /etc/cron.d/cron.allow 2>/dev/null
  cat /etc/cron.d/at.allow   2>/dev/null
  echo "\ncron.deny:"
  cat /etc/cron.d/cron.deny   2>/dev/null
  echo "\nat.deny:"
  cat   /etc/cron.d/at.deny   2>/dev/null

elif   [ "$os" = "Linux" ] ; then 
  $echo "/etc/cron.d/ :"
  ls -l /etc/cron.d/
  ##Todo: Show contents of /etc/cron.d ?
  cat /etc/cron.d/cron.allow 2>/dev/null
  cat /etc/cron.d/at.allow   2>/dev/null
  $echo "\n/etc/cron.deny:"
  cat /etc/cron.deny   2>/dev/null
  $echo "\/etc/nat.deny:"
  cat   /etc/at.deny   2>/dev/null

elif   [ "$os" = "HP-UX" ] ; then 
  tail -50 /var/adm/cron/log
  $echo "\ncron.allow:"
  cat /var/adm/cron/cron.allow 2>/dev/null
  $echo "\nat.allow:"
  cat /var/adm/cron/at.allow   2>/dev/null
  echo "\ncron.deny:"
  cat /var/adm/cron/cron.deny   2>/dev/null
  echo "\nat.deny:"
  cat /var/adm/cron/at.deny   2>/dev/null
fi


###   * Mail Services
$echo "\n---------- Mail Services ----------\n"
$echo "List of mail boxes:"
ls -lt /var/mail/*

$echo "\nChecking mail queue.."
mailq

###      * Sendmail
$echo "\n=---------- Sendmail ----------=\n"

$echo "Sendmail process:"
$ps | grep sendmail | egrep -v "grep sendmail"
process=`${proc1} | sort | uniq | grep sendmail`
[ $? = 0 ] && echo "Sendmail `which $process |egrep 'SunOS| main.c'`";
##Todo: Check sendmail error in Linux
#./lusas-basic.sh: line 1031: what: command not found

$echo "\nmailhost alias in /etc/hosts:"
grep mailhost /etc/hosts
$echo "\nChecking $aliases for programs.."
egrep -v "$comments" $aliases | grep  '|'
$echo "\nChecking $aliases for root.."
egrep '^root' $aliases 
$echo "\nsendmail.cf:"
egrep -v '^#|^$|^R|^S|^H' /etc/sendmail.cf 2>/dev/null
egrep -v '^#|^$|^R|^S|^H' /etc/mail/sendmail.cf 2>/dev/null
$echo "\nChecking /etc/mail/relay-domains .."
egrep  -v "$comments" /etc/mail/relay-domains 2>/dev/null

###      * Postfix
$echo "\n=---------- Postfix ----------=\n"

$ps | grep smtpd | egrep -v "grep smtpd"
if [ `whereis postfix|wc -w` -gt 1 ] ; then
  # postfix is installed
  $echo "\nPostfix non default settings:"
  postconf -n 2>&1

  $echo "\nfile permissions:"
  for f in `whereis postfix| awk -F: '{print $2}'` ; do ls -ld $f;  done;
  for f in `whereis postmap| awk -F: '{print $2}'` ; do ls -ld $f;  done;
  $echo "\n"
  run postfix -v -v check 2>&1
  $echo "\n"

  files="/etc/postfix/main.cf /etc/postfix/master.cf /etc/postfix/canonical /etc/postfix/recipient_canonical /etc/postfix/access /etc/postfix/virtual /etc/postfix/transport /etc/postfix/relocated /usr/local/postfix/etc/main.cf /usr/local/postfix/etc/master.cf /usr/local/postfix/etc/canonical /usr/local/postfix/etc/recipient_canonical /usr/local/postfix/etc/access /usr/local/postfix/etc/virtual /usr/local/postfix/etc/transport /usr/local/postfix/etc/relocated  "
  for f in $files ; do
    if [ -f $f ] ; then 
      $echo "\nPOSTFIX config $f..."
      egrep -v "$comments" $f
    fi
  done;
fi

###   * Database Servers
$echo "\n---------- Database Servers ----------\n"
###      * mysql
$echo "=---------- mysql ----------=\n"
$echo "\nChecking mysql:"

$echo "processes:"
$ps | grep mysqld| egrep -v "grep mysqld"

$echo "\nFile permissions:"
if [ "$os" = "Linux" ] ; then
	for f in `whereis mysqld| awk '{print $2}'` ; do ls -l $f;  done;
else
	for f in `whereis mysqld| awk -F: '{print $2}'` ; do ls -l $f;  done;
fi

# Version
$echo "\nVersion:"
run mysqladmin version

files="/etc/my.cnf /etc/mysql/my.cnf"
for f in $files; do
  if [ -f $f ] ; then 
    $echo "\nMysql config $f .."
    egrep  -v "$comments" $f 2>/dev/null
  fi
done;
files="/usr/local/mysql/data/mysqld.log"
for f in $files; do
  if [ -f $f ] ; then 
    $echo "\nMysql logs tail -50 $f .."
    tail -50 $f | egrep  -v "$comments" 2>/dev/null
  fi
done;
files="/usr/local/mysql/data /mysqldata"
for f in $files; do
  if [ -d $f ] ; then 
    $echo "\nMysql data directories $f .."
    ls -al $f/* 2>/dev/null
  fi
done;


###      * postgreSQL
$echo "\n=---------- postgreSQL ----------=\n"
$ps | grep postgres| egrep -v "grep postgres"


###      * Oracle
##Todo: Oracle checks
## http://www.faqs.org/docs/Linux-HOWTO/Oracle-7-HOWTO.html
## Find something for oracle 8-10
$echo "\n=---------- Oracle ----------=\n"
$ps | grep oracle| egrep -v "grep oracle"

## Check the oracle users home permisions and find the ORACLE_HOME dir
## Check the $ORACLE_HOME/dbs/init.ora to $ORACLE_HOME/dbs/initorcl.ora: 


###   * Clustering
$echo "\n---------- Clustering ----------\n"
###      * Heartbeat
$echo "\n=---------- Heartbeat ----------=\n"

if [ -d /etc/ha.d ]; then 
  run /etc/init.d/heartbeat status

  ##Check deamon status
  $ps | grep heartbeat| egrep -v "grep heartbeat"

  ## Read config file
  $echo "\nheartbeat .. /etc/ha.d/ha.cf"
  egrep -v "$comments" /etc/ha.d/ha.cf
  $echo ""

  $echo "heartbeat .."
  egrep -v "$comments" /etc/ha.d/haresources
  $echo ""

else
  $echo "Heartbeat is not installed"
fi

###      * drbd
$echo "\n=---------- drbd ----------=\n"

if [ -f /etc/drbd.conf ]; then 
  run /etc/init.d/drbd status

  ##Check deamon status
  $ps | grep drbd| egrep -v "grep drbd"

  ## Read config file
  $echo "\ndrbd .. /etc/drbd.conf"
  egrep -v "$comments" /etc/drbd.conf
  $echo ""
else
  $echo "drbd is not installed"
fi


###*Software, Packages*
## Send this section to it's own file
exec >"$DESTDIR/software" 2>>"$DESTDIR/software"
$echo "Running Software Module" >> "$logfile"


$echo ">>>>>>>>>> Software, Packages ----------"

###  * Installed software
$echo "---------- Installed software ----------\n"

## List the install software
##Todo: Installed software.  Complete for suse, debian, UX and BSD
if [ "$os" = "Linux" ] ; then
  if [ "$dist" = "redhat" ] ; then
	rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' > $DESTDIR/pkglist
	$echo "A complete list of installed packages was written to $DESTDIR/pkglist"

  elif [ "$dist" = "suse" ] ; then
	/bin/false

  elif [ "$dist" = "debian" ] ; then
  	dpkg -l > $DESTDIR/pkglist
	$echo "A complete list of installed packages was written to $DESTDIR/pkglist"
	/bin/false
  fi

elif [ "$os" = "SunOS" ] ; then
  pkginfo > $DESTDIR/pkglist
  $echo "A complete list of installed packages was written to $DESTDIR/pkglist"
  
elif [ "$os" = "HP-UX" ] ; then
  /bin/false
elif [ "$os" = "OpenBSD" ] ; then
  /bin/false
fi

###  * Patch level
$echo "---------- Patch level ----------\n"
$echo "\n\n Patches for $os  ------" 

##Todo: Patch level - Find a eficient way of doing this.
# - pca http://www.par.univie.ac.at/solaris/pca/ is a great solution if we can bundle it in. 
# We could bundle it with the latests patchdiag.xref so the dependencies go way down and no Internet is needed on the server
# Got to check this with sun

if [ "$os" = "SunOS" ] ; then
  showrev -p #> "$DESTDIR/showrev"                

  if [ "$VERIFY" = "1" ] ; then
    $echo "\n>>>>> package installation accuracy (ignoring permissions, group name, path)----"
    $echo "(This can be really long, but should report differences on permissions,"
    $echo " sizes etc of installed files against the Sun package database. Note that"
    $echo " its easy to modify this database, so do not rely only on this method"
    $echo " to detect unauthorised modifications of files.)"
    pkgchk -n 2>&1 | egrep -v "group name|permissions|pathname does not exist"

  else
    $echo "Skipping package checks"

  fi

elif [ "$os" = "HP-UX" ] ; then
  $echo "\nswlist -l fileset |grep PH|grep # ....."
  swlist -l fileset | grep "PH" |grep "#"
  $echo "\nswlist -l product ..."
  swlist -l product

elif [ "$os" = "Linux" ] ; then 
  $echo "\n Package DB:"
  
  if [ "$VERIFY" = "1" ] ; then
    run rpm --verify -a -i --nofiles

  else
    $echo "Skipping package checks"
  fi

##Todo: Pkg list for suse
##Todo: Make an option to make these check offline/online
	if [ "$dist" = "redhat" ] ; then 
		$echo "\nPending update:"
		run yum check-update

	elif [ "$dist" = "debian" ] ; then 
		run apt-get check
		run apt-get update -s
		run apt-get upgrade -s
	fi

elif [ "$os" = "OpenBSD" ] ; then 
  pkg_info;
fi

$echo "\nFiles with suid and sgid: stored in $DESTDIR/suid-list"
find / \( -perm -6000 -o -perm -4000 -o -perm -2000 \) -exec ls -l {} \; > $DESTDIR/suid-list

$echo "\nJava version:"
# Suse reports version on stderr! java -version 2>/dev/null
java -version 2>&1


###*Logs*
## Send this section to it's own file
exec >"$DESTDIR/logs" 2>>"$DESTDIR/logs"
$echo "Running Logs Module" >> "$logfile"

$echo "\n>>>>>>>>>> Logs ----------"

###  * Capture log files
$echo "---------- Capture log files ----------\n"
date

$echo "\nDiagnostic messages (dmesg) ------"
dmesg|egrep -v "MARK"| tail -50

$echo "\n\nLog:"
$echo "\nlist files in /var/adm /var/log/*   "
# list dirs and ignore dirs not ther (i.e. errors)
ls -l /var/log/* /var/adm/*  2>/dev/null
ls -l /var/log/*/*           2>/dev/null

if   [ "$os" = "HP-UX" ] ; then 
  $echo "\nCron log.............."
  tail -50 /var/adm/cron/log
elif   [ "$os" = "SunOS" ] ; then 
  $echo "\nCron log.............."
  tail -50 /var/cron/log
fi

# ignore for now: vold.log (23.2.03)
logs="sulog messages loginlog aculog shutdownlog rbootd.log vtdaemonlog system.log shutdownlog snmpd.log automount.log";
$echo "\nChecking /var/adm $logs";
for log in $logs ; do
  if [ -s /var/adm/$log ] ; then
    $echo "\nTail of /var/adm/$log..."
    tail -50 /var/adm/$log |egrep -v "MARK" 2>/dev/null
  fi
done

logs="messages xferlog ipflog weekly.out monthly.out adduser secure ftpd log.nmb log.smb samba.log httpd.access_log httpd.error_log mail warn Config.bootup access_log boot.msg samhain_log yule_log";
$echo "\nChecking $logs";
for log in $logs ; do
  if [ -s /var/log/$log ] ; then
    $echo "\nTail of /var/log/$log..."
    tail -50 /var/log/$log |egrep -v "MARK" 2>/dev/null
  fi
done

logs="syslog lprlog authlog maillog kernlog daemonlog alertlog newslog local0log local2log local5log sshlog cronlog" ;
for log in $logs ; do
  if [ -s /var/log/$log ] ; then
    $echo "\nTail of /var/log/$log..."
    tail -50 /var/log/$log |egrep -v "MARK" 2>/dev/null
  fi
done

$echo "\nLast 50 logins.."
run last |head -50

if   [ "$os" = "Linux" ] ; then 
  run faillog -a |head -50  2>/dev/null
fi

if [ "$os" = "SunOS" ] ; then

  $echo "\n\nChecking for crash dumps /var/crash:"
  ls -al /var/crash/*/* 2>/dev/null
  echo "You can analyse crash dumps with 'crash' or 'adb' later";
fi


##Todo: logrotate, logwatch
# logs: C2,Sulog,loginlog, cron log, accounting, /etc/utmp, utmpx, wtmp,
#  wtmpx, lastlog , SAR logs, NIS+ transaction log, ...). 
#  Are syslog messages centralised on a specially configured log server? 
#  Are all priorities/services logged? 
#  Are log files protected (file permissions)? 
#  Are they automatically pruned / compressed? How often? 

###  * Grep for common errors
$echo "\n---------- grep for common errors ----------\n"
###  * Check for log rotation
$echo "\n---------- Check for log rotation ----------\n"

###*Virtualization*
## Send this section to it's own file
exec >"$DESTDIR/virtualization" 2>>"$DESTDIR/virtualization"
$echo "Running Virtualization Module"  >> "$logfile""$DESTDIR/kernel"
$echo "\n>>>>>>>>>> Virtualization ----------"
###  * Check for Hypervisers and services
$echo "---------- Check for Hypervisers and services ----------\n"
## Linux vmware check
if [ "$os" = "Linux" ] ; then 
   $echo "vmware kernel module info:"
   /sbin/modinfo vmnet
   run /etc/init.d/vmware status

fi

###  * Check for Containers and Zones (Solaris)
##Todo:  Check if Zones are supported in earlier versions
if [ "$rel" = "5.10" ] ; then 
	$echo "---------- Check for Containers and Zones (Solaris) ----------\n"
	run zoneadm list -cv
	$echo "\nShowing the full config of each zone\n\n"
	for i in `zoneadm list -cp|cut -d: -f2 |grep -v global`; do
		run zonecfg -z $i info
		$echo "\n--\n"
	done
fi

## Redirect back to the main file
exec >>"$logfile" 2>>"$logfile"
$echo "\n\n"
$echo "Start time:	$start_time"
end_time=`date`
$echo "End time:	$end_time"
$echo ">>>>>>>>>> Done <<<<<<<<<<<"

exec >&5 2>&6

##Use $results_file to store the file name
##Create a Tar of the folder
if [ "$os" = "Linux" ]; then
	tar zcf $foldername.tar.gz $foldername
	reportfilename="$foldername.tar.gz"

elif [ -f /usr/bin/gzip ]; then
	tar cf $foldername.tar $foldername
	/usr/bin/gzip $foldername.tar
	reportfilename="$foldername.tar.gz"

else
	tar cf $foldername.tar $foldername
	compress $foldername.tar
	reportfilename="$foldername.tar.Z"
	
fi

## Send it by email
##Todo: send email - find a better way to do this
##  uuencode for Solaris is /bin/uuencode and in Linux /usr/bin/uuencode, so lets test for both before sending the email
if [ $DESTEMAIL  ]; then 
	if [ -f /usr/bin/uuencode ] || [ -f /bin/uuencode ] ; then 
		uuencode  $reportfilename $reportfilename | mail -s "$foldername" $DESTEMAIL 
		$echo "An email has been sent to $DESTEMAIL with the output"
		email_sent=1
	else
		$echo "The report couldn't be attached because uuencode is not installed on this server" | mail -s "$foldername file not attached" $DESTEMAIL
		$echo "\n\nThe report couldn't be emailed because uuencode is not installed on this server! \n\n"
	fi

fi

##Leave files on disk in either a tar.gz or a directory
if [ $LEAVE ]; then 
	$echo "Results were saved in $DESTDIR"
	rm -f $reportfilename
else
	##Delete the result directory
	$echo "Results were saved in $pwd/$reportfilename"
	rm -rf $DESTDIR
fi

##Cleanup
if [ $CLEANUP ]; then 
	$echo "Resulting files will be removed"
	rm -rf $DESTDIR
	rm -f $reportfilename
fi





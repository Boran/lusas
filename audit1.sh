#!/bin/sh
# 
# audit1.sh      http://code.google.com/p/lusas/
#
# Update dec'08: Pablo is working on a new release replacing audit1.sh with lusas-basic.sh. Checkout his design in the wiki and provide feedback via the issue queue.
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
#  ksh/sh/bash shell:   nice sh audit1.sh > `uname -n`.audit1.log 2>&1 &
#  To follow progress:  tail -f `uname -n`.audit1.log
#
#  Example cron entry to run on 20th July and mail results:
#    0 0 20 07 * /secure/audit1.sh 2>&1 |mailx -s "`uname -n` audit1" root
#  Example cron entry for server, large output expected:
#    0 0 20 07 * /secure/audit1.sh 2>&1 |compress|uuencode \
#     `uname -n`.audit1.txt.Z |mailx -s "`uname -n` audit" root 
#  On some Linux, replace 'mailx' by 'mail' in the above examples.

VERSION="audit1.sh: Oct.08, sean.boran.com/audit, Sean Boran"

# HISTORY:
#      29.Oct.08 sb Ubuntu 7.10
#      02.Nov.07 sb new: sudo, HP tweaks, mysql, SSH trusts:$
#      22.Dec.06 sb Suse: add 'siga'
#         Nov.05 sb HP-UX paths; Linux pwck
#      22.May.05 sb
#      20.Sep.04 sb new: vsftp, Apache2, chkconfig, dnsmasq
#                   Update: sendmail.cf, rc?.d list, dhcp, samba, named.....
#                   Tested: Suse 9.1, RHEL3, Solaris8
#      19.Jul.03 sb Start LDAP, more apache. Add EXTENDED option.
#                   apache fixes from S.Grundschober.
#      02.Jun.03 sb Spelling/ messages. Move Jass detection to top. Start TIPS
#                   section at the bottom.
#      27.Feb.03 sb Add /opt/sec/bin to Sun path, minor improvements
#      03.Oct.02 sb Add /usr/proc/bin to Sun path
#      05.Sep.02 sb Sun: better /proc analysis
#      17.Aug.02 sb md5 modinfo for Sun and show Sun fingerprint link
#      30.Jul.02 sb Correct securetty, ntp.conf for Linux. Apache2.i cgi-bin
#      05.Jun.02 sb Solaris ccs/md5 in PATH, /dev/random, Jass version
#                   Joel Kergozou: Check for lack of shadow file.
#      25.Mar.02 sb Apache SSH paths. Java/samba/named/sendmail/apache version.
#      10.nov.01 sb More Suse & Solaris fixes (thanks to Azim Ferchichi)
#
#      05.sep.01 sb Adapt for HP-UX11, Suse Linux 7.1
#      16.aug.01 sb fix spelling of ip_respond_to_address_mask_broadcast
#                   Improve Solaris path, detect Jass and use it. Other minor
#	            fixes.
#      25.jun.01 sb Adapt for suse 7, solaris /etc/release
#      26.Feb.01 sb Get ndd settings, add /opt/sec/bin to PATH
#      24.Jan.01 sb Minor fixes, add umask, ISS, /etc/system, kernel modules
#
#      12.Dec.00 sb Major cleanup for RedHat7, Named, Postfix...
#      21.Sep.00 sb Check samba & apache config. Stop some unnecessary warnings.
#      25.Aug.00 sb Separate "finds" into audit2.sh and also support OpenBSD.
#                   Tested on Solaris 2.6/7/8, OpenBSD 2.6, RH Linux 2.2.12-42
#      24.Jul.00 sb Check /var/crash, /var/adm/messages, snmp conf. /var/log fix
#      21.Jul.00 Sean Boran: FCS, tested on Solaris 2.7/8
#
# LICENSE:
#   This script was developed by Sean Boran, http://www.boran.com
#   It can be used/distributed for free as long as these headers are included,
#   and you send any bug fixes or improvements to sean AT boran.com.
#
# Hardening tools I can recommend:
#   Sun    - Jass, or yassp (www.yassp.org), or Titan.
#   Redhat - Bastille
#   HP     - armoring HP
#   Suse   - secchk
#
# Improvements "to do":
#  nis/nis+/domainname, umask per account
#  Password rules & aging?
#  Clean up VERBOSE/VERBOSE_SUM/FILE
#  /iplanet/server4m/bin/msg/store/bin/smtpd 
#  HP: 	for PARAM in mintm exptm lftm expwarn; do
#         /usr/lbin/getprpw -m $PARAM root | $CUT -f2 -d=
#         /usr/lbin/getprdef -m $PARAM | $CUT -f2 -d=
#       fi
#  Sun: ssadm active; list rules. Better use of /usr/proc/bin.
##################################################################

# Debugging
#set -x

# Should /etc/shadow and startup file permissions also be included?
#EXTENDED='0';
EXTENDED='1';

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

##---------- functions -------
os=`uname -s`
hw=`uname -m`
if [ "$os" = "SunOS" ] ; then
  #echo $os;
  echo='/usr/5bin/echo'
  ps='ps -ef';
  proc1='/bin/ps -e -o comm ';
  fstab='/etc/vfstab';
  shares='/etc/dfs/dfstab';
  lsof='lsof -i -C';
  mount='mount -p';
  PATH=/bin:/usr/sbin:/usr/ucb:/usr/local/bin:/usr/local/bin:/usr/local/sbin:/usr/openwin/bin:/usr/proc/bin:/opt/gnu/bin:/opt/sec/bin:/opt/sec/sbin:/opt/OBSDssh/bin:/opt/openssh/bin:/opt/sec/bin:/opt/postfix:/usr/ccs/bin:/opt/md5
  aliases='/etc/mail/aliases';
  key_progs='/usr/bin/passwd /usr/bin/login /usr/bin/ps /usr/bin/netstat /usr/sbin/modinfo';
  snmp='/etc/snmp/conf/snmpd.conf';
  crontab='crontab -l root';
  ntp='/etc/inet/ntp.conf';

elif [ "$os" = "HP-UX" ] ; then
  echo $os;
  echo='/usr/bin/echo'
  ps='ps -ef';
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
  #echo $os;
  echo='/bin/echo -e'
  #ps='ps -auwx';
  #ps='ps auwx';
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

elif [ "$os" = "OpenBSD" ] ; then
  #echo $os;
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

############### functions #######
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


############### --------- main ------------ #######################

#$echo "This system will be analysed and the results written to $f."
#$echo "Press Control-C to abort, or any key to continue.."
#read input

echo ">>>>>>>> AUDIT SCRIPT: $0 $VERSION <<<<<<<<<<<<"
echo " "
date
echo " "

# What OS release are we running?
run uname -a
if   [ "$os" = "Linux" ] ; then 
  cat /etc/lsb-release 2>/dev/null
  cat /etc/redhat-release  2>/dev/null
  cat /etc/SuSE-release 2>/dev/null
elif   [ "$os" = "SunOS" ] ; then
  cat /etc/release 2>/dev/null
fi

$echo "Logged on users:"
w

if   [ "$os" = "SunOS" ] ; then 
  $echo "-- whodo  -----------"
  whodo
fi


## Detect Sun's Jass hardening tool
if   [ "$os" = "SunOS" ] ; then
  $echo "\n>>>>> Checking for presence of The Jass hardening tool .."
  if [ -d /var/opt/SUNWjass ] ; then
    $echo "\n Jass has been run on this host - excellent!"
    $echo "Logs files of recent runs: ls -alR /var/opt/SUNWjass/run/* ..."
    ls -alR /var/opt/SUNWjass/run/*
    $echo "\n Jass version"
    cat /var/opt/SUNWjass/run/*/jass-version.txt
  fi 
  if [ -d /opt/SUNWjass ] ; then
    $echo "\n>>>>> Jass is installed - excellent!"
        /opt/SUNWjass/jass-execute -d driver.init
        /opt/SUNWjass/jass-execute -d driver.run
    $echo "We will not run the audit script since these scripts do the "
    $echo "same thing, except better :)"
    $echo "If you want to try it yourself, run:"
    $echo "    /opt/SUNWjass/jass-execute -d audit.driver\n"
  fi 
fi

$echo "\n\n>>>>> Accounts ------"
$echo "Number of accounts `wc -l /etc/passwd`"

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

## TBD: how do we do the following on HP?
## Use a regexp, special case with *?
$echo "\nAccounts with passwords (not blocked or empty)"
if   [ "$os" != "HP-UX" ] ; then
  $echo `awk -F: '{if (($2!="*") && ($2!="") && ($2!="!") && ($2!="!!") && ($2!="NP") && ($2!="*LK*")) print $1}' /etc/shadow`
else
  $echo "\nAccounts with passwords (not blocked or empty)"
  $echo `awk -F: '{if (($2!="*") && ($2!="") && ($2!="!") && ($2!="!!") && ($2!="NP") && ($2!="*LK*")) print $1}' /etc/passwd`
fi

if   [ "$os" = "HP-UX" ] ; then
  $echo "\nDuplicate Accounts"
  run logins -d -x -m
elif   [ "$os" = "SunOS" ] ; then
  $echo "\nDuplicate Accounts"
  run logins -d -x -m
fi

$echo "\nPassword settings:"
if   [ "$os" = "SunOS" ] ; then 
  $echo " /etc/default/passwd.. "
  egrep -v "$comments" /etc/default/passwd
  $echo "nsswitch.conf: `egrep '^passwd' /etc/nsswitch.conf`"
  $echo "Check dormant/invalid accounts /expiry dates: 'passwd -sa'"
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
fi

if   [ "$os" = "Linux" ] ; then 
  $echo "pwck -l"
  pwck -r
  grpck -r
fi

$echo "\nHome directory SSH trust permissions: (watch out for world/group writeable)"
#awk -F: '{print $6}' /etc/passwd | uniq| xargs ls -ld 2>/dev/null
for h in `awk -F: '{print $6}' /etc/passwd | uniq` ; do
  ls -ald $h
  if [ -f $h/.ssh/authorized_keys ] ; then
    ls -ald $h/.ssh/authorized_keys
    cat $h/.ssh/authorized_keys
  fi
done


$echo "\nsudo: /etc/sudoers..."
egrep -v "$comments" /etc/sudoers 2>/dev/null

$echo "\nConsole security..."
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


if   [ "$os" = "Linux" ] ; then 
  $echo "\nLinux security settings:"
  files="/etc/security/* /etc/rc.config"
  for f in $files ; do
    if [ -f $f ] ; then 
      $echo "\nLinux Security config... $f .."
      egrep -v "$comments" $f
    fi
  done;

  $echo "\n>>>>> Linux: kernel parameters --"
  for f in net.ipv4.icmp_echo_ignore_all net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.send_redirects net.ipv4.ip_forward net.ipv4.conf.all.forwarding net.ipv4.conf.all.mc_forwarding net.ipv4.conf.all.rp_filter net.ipv4.ip_always_defrag net.ipv4.conf.all.log_martians; do

     #echo `sysctl $f` 2>/dev/null
     sysctl $f 2>/dev/null
  done

  $echo "\n>>>>> Linux: kernel modules (modprobe -c -l) --"
  run modprobe -c -l

fi

if   [ "$os" = "HP-UX" ] ; then 
  $echo "\n>>>>> /stand/system contents--"
  egrep -v '^\*|^$' /stand/system

  $echo "\n>>>>> ndd parameters --"

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
  $echo "\n\n>>>>> Sun: strong ISS tcp sequences?--"
  egrep -v "$comments" /etc/default/inetinit 

  $echo "\n>>>>> Sun: /etc/system contents--"
  egrep -v '^\*|^$' /etc/system

  $echo "\n>>>>> Sun: ndd parameters --"
  echo "arp_cleanup_interval=`ndd /dev/arp arp_cleanup_interval`"

  ## UDP
  for f in udp_extra_priv_ports; do
    echo "$f=`ndd /dev/udp  $f`"
  done

  ## TCP
  for f in tcp_strong_iss tcp_conn_req_max_q tcp_extra_priv_ports tcp_conn_req_max_q0 tcp_time_wait_interval tcp_ip_abort_cinterval; do
    echo "$f=`ndd /dev/tcp  $f`"
  done
  $echo "\nndd TCP desired values: tcp_ip_abort_cinterval=60000 (1min) to mitigate SYN flooding. For Solaris <2.6 check also  tcp_conn_req_max."
  $echo " "
  ## IP
  $echo "\nndd IP desired values: ip_forwarding=0 ip_forward_src_routed=0 ip_forward_directed_broadcasts=0 ip_check_subnet_addr=0 ip_respond_to_echo_broadcast=0 ip_respond_to_timestamp=0 ip_respond_to_timestamp_broadcast=0 ip_send_redirects=0 ip_send_source_quench=0 "
  $echo "\nndd ip - actual values : "
  for f in ip_respond_to_timestamp ip_respond_to_address_mask_broadcast ip_ignore_redirect ip_ire_flush_interval ip_forward_src_routed ip_forward_directed_broadcasts ip_strict_dst_multihoming ip_forwarding ip_send_redirects ip6_forwarding ip6_send_redirects ip6_ignore_redirect; do
    echo "$f=`ndd /dev/ip  $f`"
  done

  $echo "\n>>>>> Sun: kernel modules loaded (modinfo) --"
  $echo   "          If you suspect a penetration, check for root kit modules."
  /usr/sbin/modinfo

fi

$echo "\n\n>>>>> Disks & mount options ------"
$echo     "          Are any disks nearly full, are partitions well allocated?"
$echo     "          Are options like ro,logging,nosuid,size used?"
run df -k
run $mount

if   [ "$os" = "SunOS" ] ; then 
  $echo "\nChecking swap:"
  run swap -l
fi

$echo "\n\n>>>>> Processes "
$echo     "      Are any enexpected processes running, are too many running"
$echo     "      as root?"
run $ps
if [ "$os" = "SunOS" ] ; then
  #$echo "\nls -l /proc (You only need to look at this if an intrusion is probable)"
  $echo "\nProcesses, and socks, from 'pfiles /proc/*"
  pfiles /proc/* | egrep 'sockname: AF_INET|peername|^[0-9]+:'| egrep -v 'sockname: AF_INET 0.0.0.0'
fi

$echo "\n\n>>>>> Is lsof installed? We can list open files, device, ports ---"
which lsof 2>/dev/null
$lsof;

$echo "\n\n>>>>> Run a checksum/hash on key binary files, it might help us "
$echo "          detect root kits, or serve as a reference for future audits."
if [ "$os" = "SunOS" ] ; then
$echo "          See also http://sunsolve.sun.com/pub-cgi/fileFingerprints.pl"
fi
for f in $key_progs ; do
  $echo "Running 'sum' and 'md5' on $f ..."
  $sum $f
  # TBD: if md5 not installed, don't run it
  md5 $f 2>/dev/null
  if [ "$os" = "SunOS" ] ; then
    $echo "Checking $f in package DB ..."
    pkgchk -p $f  2>&1
  fi
done

$echo "\n\n>>>>> Networks ------"  
$echo "Interfaces:"
if   [ "$os" = "HP-UX" ] ; then 
  lanscan
  ifconfig lan0;
  ifconfig lan1 2>/dev/null;
else
  ifconfig -a;
fi
$echo "Interface statistics:"
netstat -i;
$echo "\nRouting:"
netstat -rn;
$echo "\nNetwork connections - current:"
netstat -a

$echo "\n\n>>>>> Inetd services  -----------"
echo "Checking for inetd process.."
$ps | grep inetd
if [ -f /etc/inetd.conf ] ; then
  echo "Checking /etc/inetd.conf.."
  egrep -v "$comments" /etc/inetd.conf
fi;
if [ -f /etc/xinetd.conf ] ; then
  echo "Checking /etc/xinetd.conf.."
  egrep -v "$comments" /etc/xinetd.conf
  ls -l /etc/xinetd.d
  echo "Checking for enabled services in xinetd.."
  egrep "disable.*no"  /etc/xinetd.d/*
fi;

$echo "\nTCP Wrappers, /etc/hosts.allow: "
egrep -v "$comments" /etc/hosts.allow   2>/dev/null
$echo "/etc/hosts.deny: "
egrep -v "$comments" /etc/hosts.deny    2>/dev/null

$echo "\n\n>>>>> ftp  ------\n"
$echo "/etc/shells:"
egrep -v "$comments" /etc/shells    2>/dev/null
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
  echo "Checking /etc/xinetd.d/*ftp* .."
  ls -l /etc/xinetd.d/*ftp*
  cat /etc/xinetd.d/*ftp*
fi;

$echo "\n\n>>>>> NTP - network time protocol ---------"
$ps | grep ntpd
$echo "ntp config - $ntp:"
egrep -v "$comments" $ntp 2>/dev/null

$echo "\n\n>>>>> /dev/random ---------"
ls -l /dev/random 2>/dev/null


$echo "\n\n>>>>> SSH ---------"
# SSH daemon version
$ps | grep sshd
process=`${proc1} | sort | uniq | grep sshd`
[ $? = 0 ] && $process -invalid 2>&1|head -2|tail -1;
# SSH client version
ssh -V 2>&1
run whereis ssh

$echo "Active SSHD config:"
files="/etc /etc/ssh /usr/local/etc /opt/openssh/etc /opt/ssh/etc"
for f in $files ; do
  if [ -f $f/sshd_config ] ; then 
    echo "ssh config... $f/sshd_config .."
    egrep -v "$comments" $f/sshd_config
  fi
done;

$echo "\n\n>>>>> RPC ------"
rpcinfo -p localhost  2>/dev/null

$echo "\n>>>>> NIS+ ------"
nisls -l 2>/dev/null

$echo "\n>>>>> NFS sharing ------"
egrep -v "$comments" $shares 2>/dev/null
showmount -e          2>/dev/null
showmount -a          2>/dev/null
$echo "\n>>>>> NFS client ------" 
egrep -v "$comments" $fstab | grep nfs
$mount | grep nfs

#$echo "\n----- X11: xauth and xhost ------"  
$echo "\n\n>>>>> X11: xauth ------"  
echo "DISPLAY = `echo $DISPLAY`"
xauth list
# xhost blocks sometime (when X11 running and no display?)
#xhost
echo "ls /etc/X*.hosts : `ls /etc/X*.hosts 2>/dev/null`"

$echo "\n\n>>>>> hosts ------" 
#if   [ "$os" = "SunOS" ] ; then 
$echo "/etc/nsswitch.conf - hosts entry:"
grep hosts /etc/nsswitch.conf 
$echo "/etc/resolv.conf :"
egrep -v "$comments" /etc/resolv.conf
$echo "/etc/hosts :"
egrep -v "$comments" /etc/hosts

$echo "\n\n>>>>> SNMP , config $snmp ------" 
if [ -f $snmp ] ; then 
  egrep -v "$comments" $snmp
fi
$ps | grep snmp

$echo "\n\n>>>>> Cron ------" 
$echo "\nroot cron:"
$crontab | egrep -v "$comments"
$echo "\n"

if   [ "$os" = "SunOS" ] ; then 
  $echo "/etc/cron.d/ :"
  ls -l /etc/cron.d/
  cat /etc/cron.d/cron.allow 2>/dev/null
  cat /etc/cron.d/at.allow   2>/dev/null
  echo "cron.deny:"
  cat /etc/cron.d/cron.deny   2>/dev/null
  echo "at.deny:"
  cat   /etc/cron.d/at.deny   2>/dev/null

elif   [ "$os" = "Linux" ] ; then 
  $echo "/etc/cron.d/ :"
  ls -l /etc/cron.d/
  ## TBD: show all files in cron.d ?
  cat /etc/cron.d/cron.allow 2>/dev/null
  cat /etc/cron.d/at.allow   2>/dev/null
  $echo "cron.deny:"
  cat /etc/cron.d/cron.deny   2>/dev/null
  $echo "at.deny:"
  cat   /etc/cron.d/at.deny   2>/dev/null

elif   [ "$os" = "HP-UX" ] ; then 
  tail -50 /var/adm/cron/log
  $echo "cron.allow:"
  cat /var/adm/cron/cron.allow 2>/dev/null
  $echo "at.allow:"
  cat /var/adm/cron/at.allow   2>/dev/null
  echo "cron.deny:"
  cat /var/adm/cron/cron.deny   2>/dev/null
  echo "at.deny:"
  cat /var/adm/cron/at.deny   2>/dev/null
fi

$echo "\n\nEnvironment variables and PATH:"
$echo "(check especially for '.' in the root PATH)"
env
echo $PATH
$echo "\nroot interactive umask (should be at least 022, or better 027 or 077):"
umask
$echo "\nSearching for Daemon umasks in /sbin/init.d/*/* (to see if daemons start securely):"
egrep -v "$comments" /sbin/init.d/*  2>/dev/null | grep umask
egrep -v "$comments" /sbin/init.d/*/* 2>/dev/null | grep umask
egrep -v "$comments" /etc/init.d/*   2>/dev/null | grep umask
egrep -v "$comments" /etc/init.d/*/* 2>/dev/null | grep umask
if [ "$os" = "SunOS" ] ; then
  $echo "Default system umask: ontents of /etc/default/init:"
  egrep -v "$comments" /etc/default/init
fi

$echo "\n"
date

$echo "\n>>>>> Diagnostic messages (dmesg) ------"
dmesg|egrep -v "MARK"| tail -50

$echo "\n\n>>>>> LOGS  ------"
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

# logs: C2,Sulog,loginlog, cron log, accounting, /etc/utmp, utmpx, wtmp,
#  wtmpx, lastlog , SAR logs, NIS+ transaction log, ...). 
#  Are syslog messages centralised on a specially configured log server? 
#  Are all priorities/services logged? 
#  Are log files protected (file permissions)? 
#  Are they automatically pruned / compressed? How often? 

$echo "\n\n>>>>> Patches for $os  ------" 

if [ "$os" = "SunOS" ] ; then
  showrev -p                 

  ## Disabled: Security Focus have stopped this service.
  #$echo "\n--- Patches list for http://www.securityfocus.com/sun/vulncalc  ---" 
  #showrev -p | cut -f2 -d' '|xargs

  $echo "\n>>>>> package installation accuracy (ignoring permissions, group name, path)----"
  $echo "(This can be really long, but should report differences on permissions,"
  $echo " sizes etc of installed files against the Sun package database. Note that"
  $echo " its easy to modify this database, so do not rely only on this method"
  $echo " to detect unauthorised modifications of files.)"
  pkgchk -n 2>&1 | egrep -v "group name|permissions|pathname does not exist"

elif [ "$os" = "HP-UX" ] ; then
  $echo "\nswlist -l fileset |grep PH|grep # ....."
  swlist -l fileset | grep "PH" |grep "#"
  $echo "\nswlist -l product ..."
  swlist -l product

elif [ "$os" = "Linux" ] ; then 
  $echo "\n Auto start daemons:"
  run chkconfig --list|grep on
  $echo "\n Package DB:"
  run rpm --verify -a -i --nofiles
  # Debian based
  run apt-get check
  run apt-get update -s
  run apt-get upgrade -s

elif [ "$os" = "OpenBSD" ] ; then 
  pkg_info;
fi

if [ "$os" = "SunOS" ] ; then
  $echo "\n\n>>>>>  Eprom settings --------- "
  eeprom -v | egrep "boot|security"

  $echo "\n\n>>>>> Checking for crash dumps /var/crash  ------"
  ls -al /var/crash/*/* 2>/dev/null
  echo "You can analyse crash dumps with 'crash' or 'adb' later";
fi

$echo "\n\n>>>>> Checking Samba --------------"
$ps | grep smbd | egrep -v "grep smbd"
process=`${proc1} | sort | uniq | grep smbd`
[ $? = 0 ] && echo "Samba `$process -V`";

files="/var/log/samba /var/log.smb /var/log/log.smb"
for f in $files ; do
  if [ -f $f ] ; then 
    echo "\nsamba logs $f .."
    ls -l $f
  fi
done;

files="/usr/local/samba/lib/smb.conf /etc/samba/smb.conf"
for f in $files ; do
  if [ -f $f ] ; then 
    echo "\nsamba config $f .."
    # Samba can have comments with ';'
    egrep -v '^ *#|^$|^;' $f
  fi
done;


$echo "\n\n>>>>> Checking BIND/Named --------------"
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


$echo "\n\n>>>>> Checking DHCPD --------------"
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


$echo "\n\n>>>>> Checking LDAP --------------"
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


$echo "\n\n>>>>> Checking Apache --------------"
$ps | grep httpsd| egrep -v "grep httpsd"
for f in `whereis httpsd| awk -F: '{print $2}'` ; do ls -l $f;  done;
# Version http with SSL
process=`${proc1} | sort | uniq | grep httpsd`
[ $? = 0 ] && $process -v;

$ps | grep httpd| egrep -v "grep httpd"
for f in `whereis httpd| awk -F: '{print $2}'` ; do ls -l $f;  done;
# Version httpd
process=`${proc1} | sort | uniq | grep httpd`
[ $? = 0 ] && $process -v;

## Apache: config
files="/usr/local/apache/conf /usr/local/apache2/conf /opt/apache/conf /etc/httpd /etc/httpd/conf /etc/apache /etc/apache2 /var/www/conf /opt/portal/apache/conf"
for f in $files ; do
  if [ -f $f/httpd.conf ] ; then 
    $echo "\nhttpd config... $f .."
    egrep -v "$comments" $f/httpd.conf
  fi
  if [ -f $f/httpsd.conf ] ; then 
    $echo "\nhttpsd config... $f .."
    egrep -v "$comments" $f/httpsd.conf
  fi
done;

## Apache2
if [ -d /etc/apache2 ] ; then 
  cd /etc/apache2 
  files=`ls *conf */*conf`
  for f in $files ; do
    $echo "\nApache2: $f ..."
    egrep -v "$comments" $f
  done
fi

## Apache: error logs
files="/usr/local/apache /usr/local/apache2 /opt/apache /var/www /opt/portal/apache"
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


$echo "\n>>>>> Checking syslog config --------------"
$echo "loghost alias in /etc/hosts:"
grep loghost /etc/hosts
$echo "\nChecking /etc/syslog.conf .."
egrep  -v "$comments" /etc/syslog.conf      2>/dev/null
$echo "\nChecking /etc/syslog-ng.conf .."
egrep  -v "$comments" /etc/syslog-ng.conf      2>/dev/null
egrep  -v "$comments" /etc/syslog-ng/syslog-ng.conf      2>/dev/null
egrep  -v "$comments" /usr/local/etc/syslog-ng.conf      2>/dev/null

$echo "\n>>>>> Java version --------------"
# Suse reports version on stderr! java -version 2>/dev/null
java -version 2>&1


$echo "\n\n>>>>> List of mail boxes --------------"
ls -lt /var/mail/*

$echo "\n>>>>> Checking sendmail email config --------------"
$echo "Sendmail process:"
$ps | grep sendmail | egrep -v "grep sendmail"
process=`${proc1} | sort | uniq | grep sendmail`
[ $? = 0 ] && echo "Sendmail `what $process |egrep 'SunOS| main.c'`";
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

$echo "\n\n>>>>>  Checking SMTPD/Postfix --------------"
$ps | grep smtpd | egrep -v "grep smtpd"
if [ `whereis postfix|wc -w` -gt 1 ] ; then
  # postfix is installed
  $echo "\nPostfix non default settings:"
  postconf -n 2>&1
  for f in `whereis postfix| awk -F: '{print $2}'` ; do ls -ld $f;  done;
  for f in `whereis postmap| awk -F: '{print $2}'` ; do ls -ld $f;  done;
  $echo "\n"
  postfix -v -v check 2>&1
  $echo "\n"

  files="/etc/postfix/main.cf /etc/postfix/master.cf /etc/postfix/canonical /etc/postfix/recipient_canonical /etc/postfix/access /etc/postfix/virtual /etc/postfix/transport /etc/postfix/relocated /usr/local/postfix/etc/main.cf /usr/local/postfix/etc/master.cf /usr/local/postfix/etc/canonical /usr/local/postfix/etc/recipient_canonical /usr/local/postfix/etc/access /usr/local/postfix/etc/virtual /usr/local/postfix/etc/transport /usr/local/postfix/etc/relocated  "
  for f in $files ; do
    if [ -f $f ] ; then 
      $echo "\nPOSTFIX config $f..."
      egrep -v "$comments" $f
    fi
  done;
fi

$echo "\nChecking mail queue.."
mailq


## Detect Sun's Sunscreen Firewall
if   [ "$os" = "SunOS" ] ; then
  ssadm=/opt/SUNWicg/SunScreen/bin/ssadm
  policy=`$ssadm active 2>/dev/null|grep Active|awk '{print $5}'| sed 's/\.[0-9]*//g' `
  [ $? = 0 ] && $ssadm edit $policy -c "list rule";
fi


if [ $EXTENDED = "1" ] ; then 
  $echo "\n\n>>>>> Extended audit: add shadow file ....";        
  cat /etc/shadow    
  
  $echo "\n\n>>>>> Extended audit: permissions of startup files....";        
  for d in /etc/init.d /etc/rc2.d /etc/rc3.d /etc/rc.d; do
    if [ -d $d ] ; then
      run ls -alR $d
    fi
  done
fi


$echo "\n\n>>>>> Is siga installed? We can list the entire system HW/SW config ---"
siga 2>/dev/null
cat < /tmp/siga/siga.txt 2>/dev/null


$echo "\n\n>>>>> Checking mysql --------------"
$ps | grep mysqld| egrep -v "grep mysqld"
for f in `whereis mysqld| awk -F: '{print $2}'` ; do ls -l $f;  done;
# Version
process=`${proc1} | sort | uniq | grep mysqld`
[ $? = 0 ] && $process -V 2>&1|head -1;

files="/etc/my.cnf /etc/mysql/my.cnf"
for f in $files; do
  if [ -f $f ] ; then 
    $echo "Mysql config $f .."
    egrep  -v "$comments" $f 2>/dev/null
  fi
done;
files="/usr/local/mysql/data/mysqld.log"
for f in $files; do
  if [ -f $f ] ; then 
    $echo "Mysql logs tail -50 $f .."
    tail -50 $f | egrep  -v "$comments" 2>/dev/null
  fi
done;
files="/usr/local/mysql/data /mysqldata"
for f in $files; do
  if [ -d $f ] ; then 
    $echo "Mysql data directories $f .."
    ls -al $f/* 2>/dev/null
  fi
done;



$echo "\n\n\n......................."
date
$echo ">>>>>>>>>>>>>> DONE <<<<<<<<<<<<<<" 

###### Tips ####
#
# o compare Solaris patch levels:
# for f in *audit1.log ; do echo $f;  
#   egrep "^Patch: " $f |awk '{print $2}' |sort > $f.pat; 
# done
# sdiff system1.audit1.log.pat system2.audit1.log.pat |grep "|"
#
# To do
#  Redhat: Tail of /var/log/mail...   tail: /var/log/mail: Is a directory
#  ESX: esxcfg-firewall -q
#  echo "show databases" | mysql
######


#!/bin/sh
# 
# /secure/audit3.sh
#
# FUNCTION: 
#   Search the filesystem for unusual entries. This script is to be used
#   on systems instead of audit2.pl, if there is no perl available.
#   The idea is to generate a text file for offline analysis.
#   Tested on Suse 9, Solaris 8.
#
# USAGE: 
#  ksh/sh/bash shell:   nice time sh audit3.sh > `uname -n`.audit3.log 2>&1 &
#  To follow progress:  tail -f `uname -n`.audit3.log
#
#  Example cron entry to run on 20th July and mail results:
#    0 0 20 07 * /secure/audit3.sh 2>&1 |compress|uuencode \
#     `uname -n`.audit3.txt.Z |mailx -s "`uname -n` audit" root 
#  On Suse, replace 'mailx' by 'mail' in the above example.
#
VERSION="audit3.sh/19.Jan.04 www.boran.com/security/sp/solaris/, Sean Boran"
#
# HISTORY:
#  <1> 19.jan.04 First version to complement audit2.pl
#
# LICENSE:
#   This script was developed by Sean Boran, http://www.boran.com
#   It can be used/distributed for free as long as these headers are included,
#   and you send any bug fixes or improvements to sean AT boran.com :-)
#
##################################################################

# Debugging
#set -x

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

# Should /etc/shadow and startup file permissions also be included?
EXTENDED='1';

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
  lsof='lsof -i';
  mount='mount -p';
  PATH=/bin:/usr/sbin:/usr/ucb:/usr/local/bin:/usr/local/bin:/usr/local/sbin:/usr/openwin/bin:/usr/proc/bin:/opt/gnu/bin:/opt/sec/bin:/opt/sec/sbin:/opt/OBSDssh/bin:/opt/openssh/bin:/opt/sec/bin:/opt/postfix:/usr/ccs/bin:/opt/md5
  sendmailcf='/etc/mail/sendmail.cf';
  aliases='/etc/mail/aliases';
  smb_conf='/usr/local/samba/lib/smb.conf';
  key_progs='/usr/bin/passwd /usr/bin/login /usr/bin/ps /usr/bin/netstat /usr/sbin/modinfo';
  snmp='/etc/snmp/conf/snmpd.conf';
  crontab='crontab -l root';
  ntp='/etc/inet/ntp.conf';

elif [ "$os" = "HP-UX" ] ; then
  echo $os;
  echo='/usr/bin/echo'
  ps='ps -ef';
  proc1='/bin/ps -e -o comm ';
  fstab='/etc/fstab';
  shares='/etc/exports';
  lsof='lsof -i';
  mount='mount -p';
  PATH=/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/bin:/usr/local/sbin:/opt/sec/bin:/opt/sec/sbin:/opt/openssh/bin:/usr/local/lsof/bin:/usr/bin/X11:/opt/postfix
  sendmailcf='/etc/mail/sendmail.cf';
  aliases='/etc/mail/aliases';
  smb_conf='/usr/local/samba/lib/smb.conf';
  key_progs='/usr/bin/passwd /usr/bin/login /usr/bin/ps /usr/bin/netstat';
  snmp='/etc/SnmpAgent.d/snmpd.conf';
  crontab='crontab -l root';
  ntp='/etc/ntp.conf';

elif [ "$os" = "Linux" ] ; then
  #echo $os;
  echo='/bin/echo -e'
  ps='ps -auwx';
  proc1='/bin/ps -e -o comm ';
  fstab='/etc/fstab';
  shares='/etc/exports';
  lsof='lsof -i';
  mount='mount';
  PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:/usr/lib/saint/bin:/opt/postfix
  sendmailcf='/etc/sendmail.cf';
  smb_conf='/usr/local/samba/lib/smb.conf';
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
  sendmailcf='/etc/sendmail.cf';
  smb_conf='/usr/local/samba/lib/smb.conf';
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

############### --------- main ------------ #######################

#$echo "This system will be analysed and the results written to $f."
#$echo "Press Control-C to abort, or any key to continue.."
#read input

echo ">>>>>>>> AUDIT SCRIPT: $0 $VERSION <<<<<<<<<<<<"
echo " "
date
echo " "

# What OS release are we running?
uname -a
if   [ "$os" = "Linux" ] ; then 
  cat /etc/redhat-release 2>/dev/null
  cat /etc/SuSE-release 2>/dev/null
elif   [ "$os" = "SunOS" ] ; then
  cat /etc/release 2>/dev/null
fi
 
$echo "\n>>>>>>> Scan the system for files with no name or group: "
find / -nouser -o -nogroup -ls

$echo "\n>>>>>>> World writeable files / directories: "
find / \( -type f -o -type d \) -perm -22  -ls
echo "\n>>>>>>> suid/sgid:"
find / \( -perm -004000 -o -perm -002000 \) -type f -ls

echo "\n>>>>>>> Recently modified executables (1.Jun.03): "
touch -t 0306010000 /tmp/t
#find / -newer /tmp/t -type f -user root -perm +111 -printf "%Tc %k %h/%f\n" 
find / -newer /tmp/t -type f -user root -perm -111 -ls

echo "\n>>>>>>> Files to be checked out: "
find / -type f \( -name .exrc -o -name .htaccess -o -name htpasswd -o -name admpw -o -name magnus.conf -o -name admin.config -o -name adminacl -o -name .dbxrc -o -name .netrc -o -name .shosts -o -name .rhosts -o -name authorized_keys -o -name ssh_auth -o -name hosts.equiv -o -name .bash_history -o -name .history \) -ls

echo " "
date
echo "Done."


#!/bin/sh 
#
# /secure/audit4.sh
#
# Create a list of active tcp/udp connections and listenings in a common format
# and summarize them in a logfile avoiding very big samplefiles.
# udp Sessions cannot be sampled on every architectur
#
# 2005.06.17/sb/lb Initial version. 
#        Tested: Solaris8/9, Suse9.1, Gentoo, HP-UX, AIX
#
# Usage: Call this script, e.g. 
#          sh audit4.sh
#        and press control C when finished, look at the results 
#          audit4_HOSTNAME_summary.log
#
#        To summarise several systems together, just cat the results together
#        Finally Generate the Summary CSV files:
#          cat audit4_HOST2_summary.log audit4_HOST2_summary.log | ./audit4_summ.pl
#######

#-------------------------------------------------------------------------------
# Variables
#-------------------------------------------------------------------------------
thishost=`uname -n`
#waitfor=180			# seconds between sample
waitfor=30 			# seconds between sample
fsum=audit4_${thishost}_summary.log
flog=audit4_${thishost}.log
ftmp1=audit4_tmp1.log
ftmp2=audit4_tmp2.log
     # Explanation of log usage:
     #   Netstat is run to udp/tcp established/listening and the output sent to $ftmp1
     #   $ftmp1 is addedd to $fsum (summary), sorted, written to $ftmp2
     #   $ftmp2 is compared with fsum to find the new entries only, which are the
     #   then added to fsum
     # fsum contains a summary of activity iat each interation
     # flog contains the actual audit output that interests us.

os=`uname -s`
hw=`uname -m`
rev=`uname -r`
col1="$thishost;$os;$rev;"

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
exit_it()
{
  rm $ftmp1 $ftmp2 2>/dev/null
  echo "# Ended: `date '+%Y.%m.%d %T'`" >>$fsum
  echo "# Ended: `date '+%Y.%m.%d %T'`" >>$flog
}


#-------------------------------------------------------------------------------
# Intro
#-------------------------------------------------------------------------------
trap 'exit_it; exit' INT TERM QUIT
echo "List all active TCP/UDP sessions every $waitfor seconds to $f"
echo "Logfile:	$flog"
echo "Summary File:	$fsum"
echo "Tmp Logfile1: 	$ftmp1"
echo "Tmp Logfile2: 	$ftmp1"
date
echo "Press Control-C to quit.."
echo "# Started: `date '+%Y.%m.%d %T'`" >$fsum


#-------------------------------------------------------------------------------
# Infinite loop, stop with Control-C or kill :-)
#-------------------------------------------------------------------------------
while true; do

  if [ "$os" = "SunOS" ] ; then
    (
    # gathering Sessions
    #netstat -n -f inet -P tcp|tail +5|awk '{print "Session_tcp;" $1 ";" $2}'
    #netstat -n -f inet -P udp|tail +5|awk '{print "Session_udp;" $1 ";" $2}'
    netstat -an -f inet|awk ' $7~/ESTA|WAIT/ {print "Session_tcp;" $1 ";" $2}  $3~/Connected/ {print "Session_udp;" $1 ";" $2}'

    # gathering Listenings
    #netstat  -an -f inet -P tcp|grep LISTEN|awk '{print $1}'|awk -F'.' '{print "Listen_tcp;" col1 $NF}' col1="$col1"
    #netstat  -an -f inet -P udp|grep Idle  |awk '{print $1}'|awk -F'.' '{print "Listen_udp;" col1 $NF}' col1="$col1"
    netstat -an -f inet|awk ' $7~/LISTEN/ {print "Listen_tcp." $1}   $2~/Idle/  {print "Listen_udp." $1} ' |awk -F'.' '{print $1 ";" col1 $NF}' col1="$col1"

    ) |egrep -v '127.0.0.1' >$ftmp1

  elif [ "$os" = "HP-UX" ] || [ "$os" = AIX ]; then
    (
    # gathering Sessions
    #netstat -an -f inet|grep "^tcp"|grep ESTABLISHED|awk '{print "Session_tcp;" $4 ";" $5}' 
    #netstat -an -f inet|grep "^udp"|awk '$5 != "*.*" {print "Session_udp;" $4 ";" $5}'
    netstat -an -f inet|awk ' $6~/ESTA|WAIT/ {print "Session_tcp;" $4 ";" $5}    $3~/Connected/ {print "Session_udp;" $4 ";" $5}'

    # gathering Listenings
    #netstat -an -f inet|grep "^tcp"|grep LISTEN|awk '{print $4}'|awk -F '.' '{print "Listen_tcp;" col1 $NF}' col1="$col1" 
    #netstat -an -f inet|grep "^udp"|awk '{print $4}'|awk -F '.' '{print $NF}'|grep -v "^\*$"|awk '{print "Listen_udp;" col1 $0}' col1="$col1"
    netstat -an -f inet|awk ' $6~/LISTEN/ {print "Listen_tcp." $4}   $1~/udp/  {print "Listen_udp." $4} ' |awk -F'.'  ' $NF~/[0-9]+/ {print $1 ";" col1 $NF}' col1="$col1"
 
    ) |egrep -v '127.0.0.1' >$ftmp1


  elif [ "$os" = "Linux" ] ; then
    (
    # gathering Sessions
    #netstat -tn |tail -n +3|grep ESTABLISHED |awk '{print "Session_tcp;" $4 ";" $5}'|sed 's/:/./g'
    #netstat -un |tail -n +3|                  awk '{print "Session_udp;" $4 ";" $5}'|sed 's/:/./g'
    netstat -an |awk ' $6~/ESTA|WAIT/ {gsub(":",".",$4); gsub(":",".",$5); print "Session_tcp;" $4 ";" $5}    $3~/Connected/ {gsub(":",".",$4); gsub(":",".",$5); print "Session_udp;" $4 ";" $5}'

    # gathering Listenings (not: gsub reploace : with . to have same format as Sun/HP
    #netstat -tnl|tail -n +3|awk '{print $4}'|awk -F ':' '{print "Listen_tcp;" col1 $NF}' col1="$col1"
    #netstat -unl|tail -n +3|awk '{print $4}'|awk -F ':' '{print "Listen_udp;" col1 $NF}' col1="$col1"
    # ::: is to get rif of Ipv6
    netstat -an inet|egrep -v ':::'| awk ' $6~/LISTEN/ {print "Listen_tcp." $4}   $1~/udp/  {print "Listen_udp." $4} ' |awk -F'.'  ' $NF~/[0-9]+/ {print $1 ";" col1 $NF}' col1="$col1"

    #) |egrep -v '127.0.0.1' 
    ) |egrep -v '127.0.0.1' >$ftmp1

  elif [ "$os" = "OpenBSD" ] ; then
    echo "$os Not yet tested";
    echo='/bin/echo'

  fi

  #-----------------------------------------------------------------------------
  # Update summary log
  #   Find out  if there are new, unique entries
  #   'i' counts the number of new entries
  #-----------------------------------------------------------------------------
  cat $fsum $ftmp1 | sort -u >$ftmp2
  (
  i=`diff $ftmp2 $fsum | egrep "^<|>" | wc -l`
  #echo "`date '+%Y.%m.%d %T'`: `uname -n`: New sessions/listenings found: $i"
  if [ $i -gt 0 ] ; then echo "`date '+%Y.%m.%d %T'`: `uname -n`: New sessions/listenings found: $i"; fi
  diff $ftmp2 $fsum | egrep "^<|>"
  cp $ftmp2 $fsum
  ) >>$flog

  sleep $waitfor;

done

# eof

#!/bin/sh 
#
# /secure/audit5.sh
#
# Create a list of active tcp/udp connections by listening with
# tcpdump. Collect in a common format and summarize them in a 
# logfile avoiding very big sample files.
# Requirements: tcpdump
#
# Usage: 
#   1. Adapt the "Variables to tune per machine" section
#      Consider running tcpdump first to make sure it does what you expect
#
#   2. Call this script, e.g.
#          cd /var/tmp              [or wherever you have space]
#          sh /secure/audit5.sh     [to run in the foreground]
#          nohup sh /secure/audit5.sh &   [or background]
#
#   3. Press control C when finished, or kill if in the
#      background. 
#
#   4. To look at the results
#          audit5_HOSTNAME_summary.log
#   5. To summarise several systems together, just cat the results
#      and use ./audit5_summ.pl to generate the summary CSV files:
#          cat audit5_HOST2_summary.log audit5_HOST2_summary.log | ./audit5_summ.pl
#
# HISTORY:
#   2006.06.13/sb Better doc. Interface fixes.
#   2005.11.15/sb Summaries logs after catching kill signal
#   2005.08.11/sb Initial version.
#
# TESTED: Solaris8/9, Suse9.1, HP-UX11
#
# Copyright@2006, Sean Boran & Swisscom Innovations
####################################################

#-------------------------------------------------------------------------------
# Variables to tune per machine
#-------------------------------------------------------------------------------
DEBUG='0';                      ## '0' empty for no debugging
samples=100                     # packets to wait for between samples
#samples=1000                    # packets to wait- heavy server
waitfor=1                       # time between samples

## Where is Tcpdump? In the path? Needs sudo?
TCPDUMP_BIN='nice tcpdump';     # run it low priority (better)
#TCPDUMP_BIN='tcpdump';         # full load, should not be needed
#TCPDUMP_BIN='nice sudo tcpdump';  # Use sudo, if you don't have root!
#interface="-i eth0 "            # if there are several, or not using standard
                                 # use "tcpdump -D" to list interfaces

# Put /tmp in the path in case we have a specially compiled tcpdump
# and search a few other standard dirs
PATH=${PATH}:/tmp:/secure:/usr/local/bin:/usr/local/sbin:/bin:/usr/sbin:/usr/sbin:.
export PATH


#-------------------------------------------------------------------------------
# Standard Variables
#-------------------------------------------------------------------------------
thishost=`uname -n`
os=`uname -s`
hw=`uname -m`
rev=`uname -r`
col1="$thishost;$os;$rev;"
fsum=audit5_${thishost}_summary.log
flog=audit5_${thishost}.log
ftmp1=audit5_tmp1.log
ftmp2=audit5_tmp2.log


## Tcpdump: ignore broadcasts
#  ignore broadcasts, all icmp & udp, only get tcp session starts
#  -l=line buffered -n=don't lookup names -p=non promiscous
#  -q=quiet -t=no timestamp. 
#  -p=non promiscous (but cannot see outgoing UDP on Solaris with this! So ignore for now)
tcpdump="$TCPDUMP_BIN $interface -tqln -c $samples "

#tcpdump_expr="icmp or udp or (tcp and (tcp[13] & 0x12 == 0x12)) and not ip broadcast"
tcpdump_expr="icmp or udp or (tcp and (tcp[tcpflags] & (tcp-syn)!=0) and (tcp[tcpflags] & (tcp-ack)!=0)) and not ip broadcast"

# tcpdump notes:
# a) (tcp and tcp[tcpflags] & (tcp-syn|tcp-fin) != 0)
#    will give session start/stop, but also session attempts i.e. scans
# b) (tcp and (tcp[tcpflags] & (tcp-syn)!=0)and (tcp[tcpflags] & (tcp-ack)!=0))
#    Gives syn-ack packets which confirm initial syn and thus session start.
#    However packet is going back so session "seems" back to front

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
exit_it()
{
  echo "Quitting.."
  summarise;

  rm $ftmp1 $ftmp2 2>/dev/null
  echo "# Ended: `date '+%Y.%m.%d %T'`" >>$fsum
  echo "# Ended: `date '+%Y.%m.%d %T'`" >>$flog
}

summarise()
{
  cat $fsum $ftmp1 | sort -u >$ftmp2
  (
    #   Find out  if there are new, unique entries
    #   'i' counts the number of new entries
    #i=`diff $ftmp2 $fsum | egrep "^<|>" | wc -l`
    i=`diff $ftmp2 $fsum | egrep "^<" | wc -l`
    #echo "`date '+%Y.%m.%d %T'`: `uname -n`: New found: $i"
    if [ $i -gt 0 ] ; then  
      echo "`date '+%Y.%m.%d %T'`: `uname -n`: found: $i"; 
    fi
    diff $ftmp2 $fsum | egrep "^<|>"
    cp $ftmp2 $fsum
   ) >>$flog
}


#-------------------------------------------------------------------------------
# Intro
#-------------------------------------------------------------------------------
trap 'exit_it; exit' INT 
trap 'exit_it; exit' TERM 
trap 'exit_it; exit' QUIT
echo "Sniff active TCP/UDP/ICMP $samples at a time to $f"
echo "Final logfile:  $flog"
echo "Summary File:   $fsum"
#echo "Tmp Logfiles:   $ftmp1 $ftmp2"
#date


## Check tcpdump working
echo "Checking that tcpdump works.."
$TCPDUMP_BIN $interface -n -c 1 "$tcpdump_expr" >/dev/null
if [ $? -ne 0 ] ; then
  echo "Aborting, tcpdump not working"
  exit 1;
else
  echo "  "
  echo "tcpdump is working, start sniffing `date '+%Y.%m.%d %T'`"
  echo "# Started: `date '+%Y.%m.%d %T'`" >$fsum
  [ "$DEBUG" = "1" ] && echo "$tcpdump $tcpdump_expr"
  echo "Press Control-C to quit.."
fi

#-------------------------------------------------------------------------------
# Infinite loop, stop with Control-C or kill :-)
#-------------------------------------------------------------------------------
while true; do

  [ "$DEBUG" = "1" ] && echo "." 

  # we ignore tcpdump errors to make out easier to read, assuming that errors
  # will have been caught in the test above.

  #$tcpdump $tcpdump_expr           >$ftmp1 || exit 1
  #$tcpdump $tcpdump_expr 2>/dev/null |awk '{print $5 ";" $2 ";" $4 }' |sed 's/[,:]//g' >$ftmp1 
  $tcpdump $tcpdump_expr 2>/dev/null |awk '{print col1 $5 ";" $2 ";" $4 }' col1=$col1 |sed 's/[,:]//g' >$ftmp1 

  #-----------------------------------------------------------------------------
  # Update summary log
  #   tcpdump is run,  the output sent to $ftmp1
  #   $ftmp1 is added to $fsum (summary), sorted, written to $ftmp2
  #   $ftmp2 is compared with fsum to find the new entries only, which are the
  #   then added to fsum
  # fsum contains a summary of activity at each interation
  # The diff between fsum and ftmp tell us the effective new entries and is
  # written to flog, which contains the actual audit output that interests us.

  summarise;
  sleep $waitfor;
done


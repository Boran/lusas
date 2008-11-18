#!/usr/bin/perl
#
# name    : audit5.pl
#
# Create a list of active tcp/udp/icmp connections by listening with
# tcpdump. Collect in a common format to allow easy viewing in excel
# Ony record one row for each "connection" (optimise space)
#
# WARNING:
# This script is an optimised version of "audit5.sh", however it seg faults
# after one hour on one of my test machines, so it can't be considered
# production ready (SunOS 5.8 Generic_117350-25 sun4u, perl 5.005_03)
#
$VERSION="audit5.pl/12.Aug.05";
#
# HISTORY
#   2005.08.12/sb Initial version.
#        Tested: Solaris8/9, Suse9.1
#
# Usage: First set the path to tcpdump below, and enable debugging if you like
#        then call this script, e.g.
#          ./audit5.pl
#        and press control C when finished, look at the results
#          audit5_HOSTNAME.out   (see $flog)
#
#        To summarise several systems together, just cat the results together
#        Finally Generate the Summary CSV files:
#          echo "Machine;OS;OS ver.;Protocol;Host1;Port1;Host2;port2" > audit5.csv
#          cat audit5_*.out | egrep -v '^#' >> audit5.csv
#
# To do: 
#   1. Output is written sequentially, would be nice to write to array
#      sort it, add session counts, whether bidirectional etc.
#   2. Look up port names in /etc/services, query IP addresses
#   3. Check output file size and abort if > 100M.
#      I don't want to make a disk access for eahc packet though, so maybe
#      a separate process should do this.
#
#
#####################################



#-------------------------------------------------------------------------------
# SETTINGS: edit these 
#-------------------------------------------------------------------------------
$debug ='';                    # '1'=debug (useful), ''=no debug (quiet)
#$interface="-i eth0 ";        # if there are several, or not using standard

$ENV{'PATH'} = '/usr/bin:/usr/sbin:/bin:/sbin';

if    (-x "./tcpdump")               {$tcpdump_bin="./tcpdump"}
elsif (-x "/usr/local/bin/tcpdump")  {$tcpdump_bin="/usr/local/bin/tcpdump"}
elsif (-x "/usr/sbin/tcpdump")       {$tcpdump_bin="/usr/sbin/tcpdump"}
else  {
      $tcpdump_bin="tcpdump";     # HOPE we find it in the path
}

#-------------------------------------------------------------------------------
# Standard Variables
#-------------------------------------------------------------------------------
# security 
$ENV{'SHELL'} = '/bin/sh';
$ENV{'IFS'} = '';
umask(077);                                     # -rw-------
require "ctime.pl";

$thishost=`uname -n`; chop($thishost);
$os=`uname -s`      ; chop($os);
$hw=`uname -m`      ; chop($hw);
$rev=`uname -r`     ; chop($rev);
$col1="$thishost;$os;$rev";
$flog="audit5_${thishost}.out";
chop ($day = &ctime(time));

# tcpdump notes:
# a) (tcp and tcp[tcpflags] & (tcp-syn|tcp-fin) != 0)
#    will give session start/stop, but also session attempts i.e. scans
# b) (tcp and (tcp[tcpflags] & (tcp-syn)!=0)and (tcp[tcpflags] & (tcp-ack)!=0))
#    Gives syn-ack packets which confirm initial syn and thus session start.
#    However packet is going back so session "seems" back to front
#
#  ignore broadcasts, all icmp & udp, only get tcp session starts
#  -l=line buffered -n=don't lookup names -p=non promiscous
#  -q=quiet -t=no timestamp.
#  -p=non promiscous (but cannot see outgoing UDP on Solaris with this! So ignore for now)
#$tcpdump="nice $tcpdump_bin -tqln -c $samples $interface";
$tcpdump="nice $tcpdump_bin -tqln $interface";

#$tcpdump_expr="icmp or udp or (tcp and (tcp[13] & 0x12 == 0x12)) and not ip broadcast";
$tcpdump_expr="icmp or udp or (tcp and (tcp[tcpflags] & (tcp-syn)!=0) and (tcp[tcpflags] & (tcp-ack)!=0)) and not ip broadcast";


#-------------------------------------------------------------------------------
# functions
#-------------------------------------------------------------------------------

## Catch control-C and close files cleanly, stop tcpdump
$SIG{INT} = "aborting";	
sub aborting {
  close(CMD);
  close(LOG);
  die ("\n==> Crontrol-C pressed, closed files and aborting.\n");
}




#-------------------------------------------------------------------------------
# main()
#-------------------------------------------------------------------------------
open(STDERR, ">&STDOUT") || die "can't dup stdout";     # redirect stderr


## Check tcpdump working
$tcpdump_ok=0;
print "$VERSION\nChecking that tcpdump works, looking for ONE appropriate packet..\n";
#$cmd="$tcpdump_bin -n -c 1 |";
$cmd="$tcpdump_bin -n -c 1 \"$tcpdump_expr\" |";
#print "$cmd\n" if $debug;
open(CMD, $cmd)
  || die "can't run $cmd: __FILE__ $!\n";

  while ( <CMD> ) {
    $tcpdump_ok=1;
    print "Received: $_";
  }
close(CMD);


# ----------------------------------
## Now start the real analysis
if ($tcpdump_ok) {
  print "\n==> OK: start sniffing to $flog at $day\n";
  print "        you can monitor with tail -f $flog if needed\n";

  open(LOG, ">$flog")
    || die "can't open $flog: $!\n";
  print LOG "# Started: $day\n";
  # Write logs to disk immediately
    $oldh = select(LOG);
    $| = 1;
    select($oldh);
  print "        Press Control-C to quit..\n";


  $cmd="$tcpdump  \"$tcpdump_expr\" |";
  #print "TCPDUMP: $cmd\n" if $debug;
  open(CMD, $cmd) || die "can't run $cmd: __FILE__ $!\n";

  while ( $line = <CMD> ) {
    #print "Received: $line";
    # IP 193.5.238.11.37502 > 193.5.238.15.514: UDP, length 148
    # IP 193.5.227.16 > 193.5.238.15: ICMP echo request, id 42301, seq 1, length 64

    if ($line =~ /^(\S+) (\S+) > (\S+): (UDP|udp|icmp|ICMP|tcp|TCP)/) {

      $from=$2;$to=$3;$proto=$4;
      @from_fields = split(/\./, $from);
      @to_fields   = split(/\./, $to);
      $from="$from_fields[0].$from_fields[1].$from_fields[2].$from_fields[3]";
      $to  ="$to_fields[0].$to_fields[1].$to_fields[2].$to_fields[3]";
      $from_port=$from_fields[4];
      $to_port  =$to_fields[4];
      #print "RAW:$proto;$from;$from_port;$to;$to_port;\n";


      if (($proto eq "tcp") || ($proto eq "TCP")) {  #####
        print "RAW tcp:$proto;$from;$from_port;$to;$to_port;\n" if $debug;
        # Find duplicates: have there been other packets where $to;$to_port;$from
        # are the same? Only from_port differs, i.e. we've seen this already?
        # Examine $from_port because the packets we recorded are SYN-ACK replies

        $session_id="$to;$from;$from_port";   # ignore "high" source port
        if ( defined $tcp_session{$session_id} ) {
          $tcp_session{$session_id}++;
          if ($tcp_session{$session_id}==2) {    # Debugging: note once
            print "Ignoring multiple tcp session: $to;$to_port;$from;$from_port;$tcp_session{$session_id}\n" if $debug;
          }
        } else {
          $tcp_session{$session_id}=1;

          ## OK, save this session:
          # Reverse the from/to since we recorded SYN-ACKs which is the reply
          # packet to initial session request
          #push @established, "$col1;TCP;$to;$to_port;$from;$from_port\n";
          print LOG "$col1;TCP;$to;;$from;$from_port\n";
        }


      } elsif (($proto eq "UDP") || ($proto eq "udp")) {  #####
        #print "RAW UDP:$from;$from_port;$to;$to_port;\n";
        ## Reduce standard well-known UDP ports: syslog,ntp,snmp,dns
        if (  ($to_port =~  /^(53|111|123|161|514)$/) 
           || ($from_port =~  /^(53|111|123|161|514)$/) ) {

          # Find duplicates: have there been other packets where $to;$from
          # are the same? i.e. we've seen this already?
          $session_id="$to;$from;$to_port";    # one direction
          $session_id2="$from;$to;$from_port"; # the other

          if ( defined $udp_session{$session_id} ) {
            $udp_session{$session_id}++;

            if ($udp_session{$session_id}==2) {    # Debugging: note once
              print "Ignoring UDP: $proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;
            }

          } elsif ( defined $udp_session{$session_id2} ) {
            # Were there already packets in the other direction?

            print "Ignoring UDP reverse: $proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;

          } else {
            # never been seen before, save this packet:
            $udp_session{$session_id}=1;

            print LOG "$col1;UDP;$to;$to_port;$from;$from_port;\n";
            # Don't print the from_port if its a high port
            #if ($from_port eq $to_port) {
            #  print LOG "$col1;UDP;$to;$to_port;$from;$from_port;\n";
            #} else {
            #  print LOG "$col1;UDP;$to;$to_port;$from;;\n";
            #}
          }

        }

      } elsif (($proto eq "ICMP") || ($proto eq "icmp")) {  #####
        #IP 193.5.238.25 > 193.5.238.15: ICMP echo reply, id 23837, seq 0, length 64
        #print "RAW ICMP:$from;$from_port;$to;$to_port;\n";

        # Find duplicates: have there been other ICMP packets where $to;$from
        # are the same? i.e. we've seen this already?
        $session_id="$to;$from";
        $session_id2="$from;$to";

        if ( defined $icm_session{$session_id} ) {
          $icm_session{$session_id}++;
          if ($icm_session{$session_id}>1) {    # Debugging: note once
            print "Ignoring ICMP: $proto_s;$from;$from_port;$to;$to_port;$icm_session{$session_id}\n" if $debug;
          }

        } elsif ( defined $icm_session{$session_id2} ) {
          # Were there already packets in the other direction?
          print "Ignoring ICMP reverse: $proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;

        } else {
          # never been seen before, save this packet:
          $icm_session{$session_id}=1;
          print LOG "$col1;ICMP;$to;;$from;;\n";

        }

      } else {   # tcp/udp/icmp
        print "Unknown, not tcp/udp/icmp: $line";
      }

    } else {   # $line
      print "Unparsed tcpdump output: $line";
    }
    
  } # while
  close(CMD);


  ## clean up ##
  close(LOG);
  print "\nDone.\n";

} else {
  print "Aborted, $tcpdump_bin not working!\n";
  exit 1;

}   ## The end!

#!/usr/bin/perl
#
# name    : audit5_summ.pl
# FUNCTION: Summarise results from audit5.sh on several machines.
#           We ignore multiple ICMP & tcp sessions with same from/to IP.
#           UDP: ignore multiple packets to ports 514|53|123 with same from/to IP.
# 
# USAGE:    cat audit5_*summary.log| ./audit5_summ.pl
#           results are written to $matrix1='audit5.csv', and can be opened in Excel.
#
# History :
#   2005.8.12/sb First version, Sean Boran
# 
# TESTED ON: Solaris 8
#
# Possible improvements for future:
#          Create detailed log with timestamps, "session" counts etc.
#          Output to mysql to allow extensive querying of results
#
##################

$debug ='';		# '1'=debug (useful), ''=no debug (quiet)
$services_file='/etc/services'; #
$matrix1='audit5.csv';   # file name for list of active servers

# --- perl security precautions ---
$ENV{'PATH'} = '/usr/bin:/usr/sbin:/bin:/sbin:/usr/etc';
$ENV{'SHELL'} = '/bin/sh';
$ENV{'IFS'} = '';
umask(077);                             	# -rw-------

$os=`uname -r`;					# Get OS revision
$os_name=`uname -s`;				# Get OS name
#print "uname -s returns $os_name\n" if $debug;

#goto SKIP;

if ( -s "services" ) {   # found local services
  $services_file='./services';
} else {
  $services_file='/etc/services';
}
print "Using $services_file for portname lookup.\n";

## Read in a service definiton file
open(F, "<$services_file");
while($line = <F>) {
  chop($line);
  #print "LINE: $line\n";
  if ($line =~ /^#/) {
    ;  # skip comments

  } elsif ($line =~ /^(\S+)\s+(\d+)\/(tcp|udp)\s+(\S+)\s+#(.*)/) {
    ## First Format:
    ## systat           11/tcp    users        # Active Users

    $proto=uc($3);  # Uppercase
    #print "Name=$1,Port=$2,Proto=$proto,Comment=$5\n";
    # store port name in $services[proto][port_no]
    if (! defined( $services{$proto}{$2}{'name'} )) {
      $services{$proto}{$2}{'name'}=$1;
    }
    if (! defined( $services{$proto}{$2}{'comment'} )) {
      $services{$proto}{$2}{'comment'}=$5;
    }

  } elsif ($line =~ /^(\S+)\s+(\d+)\/(tcp|udp)\s+# *(.*)$/) {
    ## 2nd Format:
    ## telnet           23/tcp    # Telnet
    $proto=uc($3);  # Uppercase
    #print "Name=$1,Port=$2,Proto=$proto,Comment=$4\n";
    # store port name in $services[proto][port_no]
    if (! defined( $services{$proto}{$2}{'name'} )) {
      $services{$proto}{$2}{'name'}=$1;
    }
    if (! defined( $services{$proto}{$2}{'comment'} )) {
      $services{$proto}{$2}{'comment'}=$5;
    }

  } elsif ($line =~ /^(\S+)\s+(\d+)\/(tcp|udp).*/) {
    ## 3nd Format:
    ## ftp-data         20/tcp

    $proto=uc($3);  # Uppercase
    #print "Name=$1,Port=$2,Proto=$proto\n";
    # store port name in $services[proto][port_no]
    if (! defined( $services{$proto}{$2}{'name'} )) {
      $services{$proto}{$2}{'name'}=$1;
    }

  } else {
    # Stuff like sctp,ddp,tdp will be left
    #print "Services not parsed: $line\n";
  }
  next;
} # finished reading input
close(F);



SKIP:
## Main loop from stdin
while($line = <STDIN>) {
  chop($line);
  
  ## build matrix
  #if ($line =~ /(icmp|ICMP|tcp|TCP|UDP|udp)/) {

  ## TCP
  if ($line =~ /(tcp|TCP)/) {        # TCP is special
    @fields = split(/;/, $line);
      #host5;SunOS;5.9;tcp;10.5.233.53.22706;10.5.227.11.3813

      $proto_s=$fields[3];
      @from_fields = split(/\./, $fields[4]);
      @to_fields   = split(/\./, $fields[5]);
      $from="$from_fields[0].$from_fields[1].$from_fields[2].$from_fields[3]";
      $to  ="$to_fields[0].$to_fields[1].$to_fields[2].$to_fields[3]";
      $from_port=$from_fields[4];
      $to_port  =$to_fields[4];

      # Find duplicates: have there been other packets where $to;$to_port;$from
      # are the same? Only from_port differs, i.e. we've seen this already?
      # Examine $from_port because the packets we recorded are SYN-ACK replies
      # (see audit5.sh).
      $session_id="$to;$from;$from_port";  # usual case
      $session_id2="$to;$from;$to_port";   # reverse connections, e.g. FTP/20

      if ( defined $tcp_session{$session_id} ) {
        $tcp_session{$session_id}++;
        if ($tcp_session{$session_id}==2) {    # Debugging: note once
          print "Ignoring multiple tcp session: $fields[0];$fields[1];$fields[2];TCP;$to;$to_port;$from;$from_port;$tcp_session{$session_id}\n" if $debug;
        }

      } elsif ($to_port eq "20") {   # reduce reverse FTP data connections

        if ( defined $tcp_session{$session_id2} ) {
          print "Ignoring multiple tcp FTP session: $fields[0];$fields[1];$fields[2];TCP;$to;$to_port;$from;$from_port;$tcp_session{$session_id2}\n" if $debug;

        } else {
          $tcp_session{$session_id2}=1;
          push @established, "$fields[0];$fields[1];$fields[2];TCP;$to;20 ftp-data;$from;\n";
        }

      } else {
        $tcp_session{$session_id}=1;

        ## OK, save this session:
        # Reverse the from/to since we recorded SYN-ACKs which is the reply
        # packet to initial session request
        #push @established, "$fields[0];$fields[1];$fields[2];TCP;$to;$to_port;$from;$from_port\n";
        $to_p=$to_port     .' ' .$services{'TCP'}{$to_port}{'name'} 
                           .' ' .$services{$proto_s}{$to_port}{'comment'};
        $from_p=$from_port .' ' .$services{'TCP'}{$from_port}{'name'} 
                           .' ' .$services{$proto_s}{$from_port}{'comment'};;
        push @established, "$fields[0];$fields[1];$fields[2];TCP;$to;$to_p;$from;$from_p\n";
      }


  ## ICMP
  } elsif ($line =~ /(icmp|ICMP)/) {

    @fields = split(/;/, $line);
      #host1;SunOS;5.8;ICMP;10.176.214.30;10.5.238.99

      $proto_s=$fields[3];
      @from_fields = split(/\./, $fields[4]);
      @to_fields   = split(/\./, $fields[5]);
      $from="$from_fields[0].$from_fields[1].$from_fields[2].$from_fields[3]";
      $to  ="$to_fields[0].$to_fields[1].$to_fields[2].$to_fields[3]";
      $from_port=$from_fields[4];
      $to_port  =$to_fields[4];

      # Find duplicates: have there been other ICMP packets where $to;$from
      # are the same? i.e. we've seen this already?
      $session_id="$to;$from";
      $session_id2="$from;$to";

      if ( defined $icm_session{$session_id} ) {
        $icm_session{$session_id}++;
        if ($icm_session{$session_id}==2) {    # Debugging: note once
          print "Ignoring ICMP: $fields[0];$fields[1];$fields[2];$proto_s;$from;$from_port;$to;$to_port;$icm_session{$session_id}\n" if $debug;
        }

      } elsif ( defined $icm_session{$session_id2} ) {
        # Were there already packets in the other direction?
        print "Ignoring ICMP reverse: $proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;


      } else {
        $icm_session{$session_id}=1;
        ## OK, save this packet:
        #push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;$from_port;$to;$to_port\n";
        push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;;$to;\n";
      }



  ## UDP
  } elsif ($line =~ /(UDP|udp)/) {

    @fields = split(/;/, $line);
      #host2;SunOS;5.8;UDP;10.32.17.13.123;10.5.238.99.123
      #print "Established $proto_s Fields: $fields[1], $fields[2]\n";

      $proto_s=$fields[3];
      @from_fields = split(/\./, $fields[4]);
      @to_fields   = split(/\./, $fields[5]);
      $from="$from_fields[0].$from_fields[1].$from_fields[2].$from_fields[3]";
      $to  ="$to_fields[0].$to_fields[1].$to_fields[2].$to_fields[3]";
      $from_port=$from_fields[4];
      $to_port  =$to_fields[4];

      ## Reduce standard well-known UDP ports: syslog,ntp,snmp,dns,netbios,nfs
      if ($to_port =~  /^(53|111|123|161|162|514|137|139|2049)$/) {
        
        # Find duplicates: have there been other packets where $to;$from
        # are the same? i.e. we've seen this already?
        $session_id="$to;$from;$to_port";    # one direction
        $session_id2="$from;$to;$from_port"; # the other

        if ( defined $udp_session{$session_id} ) {
          $udp_session{$session_id}++;

          if ($udp_session{$session_id}==2) {    # Debugging: note once
            print "Ignoring multiple UDP: $fields[0];$fields[1];$fields[2];$proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;
          }

        } elsif ( defined $udp_session{$session_id2} ) {
          # Were there already packets in the other direction?
          print "Ignoring UDP reverse: $proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;


        } else {
          # never been seen before, save this packet:
          $udp_session{$session_id}=1;

          $to_p=$to_port     .' ' .$services{'UDP'}{$to_port}{'name'} 
                             .' ' .$services{$proto_s}{$to_port}{'comment'};
          $from_p=$from_port .' ' .$services{'UDP'}{$from_port}{'name'} 
                             .' ' .$services{$proto_s}{$from_port}{'comment'};;

          #push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;$from_port;$to;$to_port\n";
          # Don't print the from_port if its a high port
          if ($from_port eq $to_port) {
            push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;$from_p;$to;$to_p\n";
          } else {
            push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;;$to;$to_p\n";
          }
        }

      ## Reduce standard well-known UDP ports: syslog,ntp,snmp,dns
      } elsif ($from_port =~  /^(53|111|123|161|514|137|139|2049)$/) {

        # Find duplicates: have there been other packets where $to;$from
        # are the same? i.e. we've seen this already?
        $session_id2="$to;$from;$to_port";    # one direction
        $session_id="$from;$to;$from_port";   # the other

        if ( defined $udp_session{$session_id} ) {
          $udp_session{$session_id}++;

          if ($udp_session{$session_id}==2) {    # Debugging: note once
            print "Ignoring multiple UDP: $fields[0];$fields[1];$fields[2];$proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;
          }

        } elsif ( defined $udp_session{$session_id2} ) {
          # Were there already packets in the other direction?
          print "Ignoring UDP reverse: $proto_s;$from;$from_port;$to;$to_port;$udp_session{$session_id}\n" if $debug;

        } else {
          $udp_session{$session_id}=1;
          ## OK, save this packet:
          $to_p=$to_port     .' ' .$services{'UDP'}{$to_port}{'name'} 
                             .' ' .$services{$proto_s}{$to_port}{'comment'};
          $from_p=$from_port .' ' .$services{'UDP'}{$from_port}{'name'} 
                             .' ' .$services{$proto_s}{$from_port}{'comment'};;
          #push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;$from_port;$to;$to_port\n";
          # Don't print the to_port if its a high port
          if ($from_port eq $to_port) {
            push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;$from_p;$to;$to_p\n";
          } else {
            push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;$from_p;$to;\n";
          }
        }

      } else {
        # other UDP protocol
        push @established, "$fields[0];$fields[1];$fields[2];$proto_s;$from;$from_port;$to;$to_port\n";

      }

  }  # if line (protocol)

  next;
} # finished reading input

#foreach $p (sort keys %mat) {
#  print "Port $p\n";
#}



####### now print analysis
print ("Writing Active matrix to: $matrix1\n");
open(F, ">$matrix1");
  print F  "Host;OS;OS-version;Proto;From IP;From Port;To IP;To Port\n";
  foreach $line (sort @established) {
    print F  $line;
  }
close(F);

#eof

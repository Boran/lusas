#!/usr/bin/perl
#
# name    : audit4_summ.pl
#
# FUNCTION: Summarise results from audit4.sh on several machines.
# 
# USAGE:    cat results1 results2 | ./audit4_summ.pl
#
# History :
#   2006.6.17/sb First version
#   2006.6.20/sb Add local services file.
# 
# TESTED ON: 

$debug ='';			# '1'=debug (useful), ''=no debug (quiet)
$services_file='/etc/services'; #
$matrix1='matrix_listen.csv';   # file name for list of active servers
$matrix2='matrix_est.csv';      # file name for established session
$bad_ports1='^9$|^19$|^23$|^514$|^515$|^544$|^636$';  
   # Ports we recommend to block

# --- perl security precautions ---
$ENV{'PATH'} = '/usr/bin:/usr/sbin:/bin:/sbin:/usr/etc';
$ENV{'SHELL'} = '/bin/sh';
$ENV{'IFS'} = '';
umask(077);                             	# -rw-------

$os=`uname -r`;					# Get OS revision
$os_name=`uname -s`;				# Get OS name
#print "uname -s returns $os_name\n" if $debug;

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
  if ($line =~ /^(\S+)\s+(\d+)\/(tcp|udp)\s+(\S*)\s*#*\s*(.*)/) {

    #print "Name=$1,Port=$2,Proto=$3,Comment=$5\n";

    # store port name in $services[proto][port_no]
    if (! defined( $services{$3}{$2}{'name'} )) {
      $services{$3}{$2}{'name'}=$1;
    }
    if (! defined( $services{$3}{$2}{'comment'} )) {
      $services{$3}{$2}{'comment'}=$5;
    }
  }
  next;
} # finished reading input
close(F);


## Main loop from stdin
while($line = <STDIN>) {
  chop($line);
  
  ## First build listen matrix
  if ($line =~ /Listen_(tcp|udp)/) {
    $proto=$1;

    @fields = split(/;/, $line);

      # Merge hosts fields to one
      #$host="$fields[1];$fields[2];$fields[3]";
      $host=$fields[1];
      $port=$fields[4];
      #print "$proto $port\n";

    if (! defined( $matrix2{$host} )) {
      $matrix2{$host}=$fields[2];
    }
    if (! defined( $matrix3{$host} )) {
      $matrix3{$host}=$fields[3];
    }

    # Save list of ports found, by port
    if (! defined $mat{$port}) { $mat{$port}=1 };

    # Save list of ports found, by host,protocol
    if (! defined( $matrix{$host}{$proto}{$port} )) {
      $matrix{$host}{$proto}{$port}=1; 
    }

  }  
  ## established matrix ####
  elsif ($line =~ /Session_(tcp|udp);/) {
    $proto_s=$1;
    @fields = split(/;/, $line);
    #print "Established $proto_s Fields: $fields[1], $fields[2]\n";
    if ($fields[1] =~ /127.0.0.1/) {
      # ignore for now
    } else  {
      @from_fields = split(/\./, $fields[1]);
      @to_fields   = split(/\./, $fields[2]);
      $from="$from_fields[0].$from_fields[1].$from_fields[2].$from_fields[3]";
      $to  ="$to_fields[0].$to_fields[1].$to_fields[2].$to_fields[3]";
      $from_port=$from_fields[4];
      $to_port  =$to_fields[4];

      #print "$proto_s;$from;$from_port;$to;$to_port\n";
      push @established, "$proto_s;$from;$from_port;$to;$to_port\n";
    }

  }  # if line

  next;
} # finished reading input

#foreach $p (sort keys %mat) {
#  print "Port $p\n";
#}



####### now print analysis

print ("Writing Listen matrix to: $matrix1\n");
open(F, ">$matrix1");

  ## Title line, sort ports by number
  # The meat:
  print F "Host;Service;Service Description;Comment;";
  foreach $host (sort keys %matrix) {
    print F "$host;";
  }
  print F "\n";

  print F "OS;;;;";
  foreach $host (sort keys %matrix) {
    print F "$matrix2{$host};";
  }
  print F "\n";

  print F "OS rev;;;;";
  foreach $host (sort keys %matrix) {
    print F "$matrix3{$host};";
  }
  print F "\n";


 ## list all tcp, then ports
 foreach $proto ('tcp','udp') {

  foreach $p (sort {$a<=>$b} keys %mat) {
    # Get service name, for tcp and udp
    #($srv1,$x,$x)=getservbyport($p,$proto);
    #$line= "Port $proto $p $srv1";
    $srv1=$services{$proto}{$p}{'name'};
    $line= "Port $proto $p;$services{$proto}{$p}{'name'};$services{$proto}{$p}{'comment'};";
    $found_flag=0;

    foreach $host (sort keys %matrix) {
        if ($matrix{$host}{$proto}{$p}==1) {
          #$line=$line . ";$p";
          $line=$line . ";X";
          $found_flag=1;
        } else {
          $line=$line . "; ";
        }
    }

    if ($found_flag==1) {print F "$line\n";}
  }
 }

close(F);


print ("Writing Active matrix to: $matrix2\n");
open(F, ">$matrix2");
  print F  "Proto;From IP;From Port;To IP;To Port\n";
  foreach $line (sort @established) {
    print F  $line;
  }
close(F);


#eof

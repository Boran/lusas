#!/usr/bin/perl
#
# NAME    : audit2.pl
# FUNCTION: Search for SUID, worldwriteable, trust, hacker,
#           sensitive and weird files.
#           Read the default settings for your OS below. Test first!
#           It's very fast but can take TIME on a big box. 
#           Set debug=1 to better understand what is happening.
#           If you don't have perl on the target system, check out
#           'audit3.sh' as an alternative.
# 
# USAGE:    Edit SETTINGS section below, then:
#              nice perl audit2.pl
#           There can also be a first argument, which is interpreted as ONE
#           filesystem only to be analysed. We use 'nice' to reduce the effect
#           on system performance (especially important on production systems)
#
$VERSION="audit2.pl/Oct.09";
# History :
#      29.Oct.08 sb Add $exclude_dirs, $group_rw
# <13> 19.Jan.04 sb Update comments
#      --- 2003 ---
# <12> 10.Mar.03 sb Check for prefs.js.
# <11> 02.Jan.03 sb Improve $get_fs_cmd for Linux, fix weirds.
#      --- 2002 ---
# <10> 03.Oct.02 sb Fix regexp added in <3>  :-)
#  <9> 14.Sep.02 sb Detect apache worm (/tmp/.bugtraq)
#  <8> 16.Aug.02 sb Fix to $exclude
#  <7> 23.Jul.02 sb print file counts even if 0, so we remind what
#                   has actually been audited.
#      06.Jun.02 sb Fix Joel Kergozou: ifconfig improvements.
#      05.May.02 sb Ignore "$" files, too many java classes as FPs.
#      --- 2001 ---
#      05.sep.01 sb Adapt for HP-UX 11, put '&' in front of functions for less
#                   forgiving perl versions. Allow '!' is files (don't detect
#                   as 'weird' (reduce false positives). Add '$' to 
#                   'veryweirds'. Ignore sgid directories. Detect KOH worm.
#                   Fix pruning, ignore filesystems in $exclude. Suse 7.1.
#      06.Aug.01 sb Default output file in current dir. 'ls' errors to log,
#		    not stderr.
#      19.May.01 sb Detect cheese worm
#  <6> 09.Apr.01 sb Detect dmi hack kit, Adore worm, ARK rootkit. Reorganise 
#                   $weirds. $mode correct for group write files.
#  <5> 23.Mar.01 sb Detect Lion/t0rn('.lib's). Use Disksuite disks(P.Bayle).
#  <4> 15.Feb.01 sb Detect Ramen, histories, netscape. Count files.
#      --- 2000 ---
#  <3> 21.Dec.00 sb Improve regexps, emailing results is now optional
#                   Only report GID if not SUID. Use variable for regexps.
#                   Only report world write if not group write. Detect John.
#                   Detect Veritas filesystems & analyse.
#  <2> 25.Aug.00 sb Rewrite as auditing script.
#  <1> V1.1 (Sean Boran) 1995
# 
# TESTED ON: 
#    Perl4 doesn't work: only tested once on HPUX
#    Perl5 + SunOS 5.5/6/7/8/9, OpenBSD 2.6, RedHat7, Suse7.1, HP-UX11
#    (Does NOT work on RH 6.0 Linux- broken "uname" in perl)
#
# LICENSE:
#      This script was developed by Sean Boran, http://www.boran.com.
#      It can be distributed for free as long as these headers are included.
#      Please send any bug fixes or improvements to sean AT boran.com.
#
# To Do:
# - list binaries changed within the last 6 months
# - command line options for results file, email & debug options
# - config known file lists for worldwrite and suid, to report size
# - md5?
# - on sensitive files only report if size >0
###################################################################


# =======> SETTINGS: edit these variables if needed <===============

$exclude ='/backup|/dev/shm|/dev';     # Don't examine these filesystems
                              # ignore /dev for newer linux

# do not search these directories
$exclude_dirs='^\/home\/test1|^\/home\/test2';  

$group_rw = '';		        # '1'=Report group-writeable files (often a huge list we don't care about)

$debug ='';			# '1'=debug (useful), ''=no debug (quiet)
$debug2='0';			# '1'=print results to terminal also
                                # (default is to write to file only)
$email_results='0';		# '0'=write to file, don't email
$user='root';                   # send email to him/her

$aggressive = '0';		# '1'=Immediately DELETE baddies
                                # DO NOT DO THIS unless you
                                # have reviewed these sources and tested on a
 				# non-production machine first..

# ======== end of SETTINGS ==============


# == more variables
$hostname=`uname -n`;  chop($hostname);
$tmpfile = "$hostname.audit2.$$.log";  # put results here

# == Regexps (for experts only, be v.careful) <3> ===========

# Preamble: "veryweird" files that contain '\' '"' or '$' 
# are not examine at all, since we can't handle them
# see <##> below

# a) files that could be critical
$configs='^\.exrc$|^\..*history$|^\.htaccess$|tomcat-passwd.xml|htpasswd$|^admpw|^magnus.conf|^admin.config|^adminacl|^.dbxrc|^.dbxinit|^.netrc'; 

# b) Trust files
$trusts='^\.[sr]hosts$|authorized_keys|ssh_auth|hosts.equiv$'; 

# c) Signs of hacker tools and weird files/directories
# Patterns are on separate line to ease reading. 
# Detect: ramen, john the ripper, solaris kernel module trojan, Linux LKM rootkit, Lion, dmi hack kit, Adore worm, ARK

#$weirds='^\.\..+|;|\'|!|' .
$weirds='^\.\..+|;|\'|' .
'.poop|' .
'^john.(ini|pot)|' .
'ramen.tgz|' .
#'^sklm|' .
'^sitf0|' .
'xlogin$|' .
'^ld.so.hash$|' .
'^unhack.pl$|' .
'^crtz.o$|' .
'^\.t0rn$|' .
#'^\.config$|' .
'^ava$|' .
'^ex3.c$|' .
'^li0n\.(tgz|sh)|' .
'^stealth.c$|' .
'^rh6kit.tar.gz$|' .
#'^\.lib|' .
'^\/dev\/pts\/01$|' .
'^\/usr\/lib\/lib$|' .
'^\/usr\/bin\/adore$|' .
'^\/tmp\/\.cheese|' .
'^\/dev\/ptyxx\/\.(log|file|proc)|'.
'^\/usr\/bin\/no$|' .
'^\/var\/\.(prc|kls|adr)$|' .
'^prefs\.js$|' .
'^\/tmp\/\.bugtraq' ;

#print $weirds;

# ====================== end of SETTINGS ========================

require "find.pl";
require "ctime.pl";

# --- perl security precautions ---
$ENV{'PATH'} = '/usr/bin:/usr/sbin:/bin:/sbin:/usr/etc';
$ENV{'SHELL'} = '/bin/sh';
$ENV{'IFS'} = '';
umask(077);                             	# -rw-------

chop ($day = &ctime(time));
$day  =~ s/^\w+ (\w+ +\d+) .*/\1/;		# get date in "Oct  5" format

## Set system specific commands
$os=`uname -r`;					# Get OS revision
$os_name=`uname -s`;				# Get OS name
#print "uname -s returns $os_name\n" if $debug;

## The $get_fs_cmd is important and must return a list of local filesystems,
## excluding cdrom, floppies, loopbacks and remote NFS, since there' no point
## in analysing those, is there?
if ($os =~ /^4\.1\.\d/) {			# It's SunOS 4.1.x
    print "OS = Sun 4.1.x\n" if $debug;
    $mail='/usr/ucb/mail';		
    $get_fs_cmd ="/usr/etc/mount | egrep '/dev/sd' | cut -d' ' -f3";
    $ifconfig_cmd ="/usr/etc/ifconfig -a 2>&1 | fgrep UP | fgrep -v lo0";
    $ifconfig_list ="ifconfig -a|grep inet|grep -v '127\.0\.0\.1'";
}
elsif (($os_name = "SunOS") && ($os =~ /^5\.\d/)) {  # Solaris 2.x
    print "OS = Sun 5.x\n" if $debug;
    $mail='/usr/bin/mailx';
    $get_fs_cmd ="/usr/sbin/mount |egrep -v '/vol/dev/dsk' |egrep '/dev/dsk/|/dev/vx/dsk|/dev/md/dsk' |cut -d' ' -f1";
    $ifconfig_cmd ="/sbin/ifconfig -a 2>&1 | fgrep UP | fgrep -v LOOPBACK";
    $ifconfig_list ="/sbin/ifconfig -a|grep inet|grep -v '127\.0\.0\.1'";
}
elsif (($os_name = "Linux") && ($os =~ /^2\.\d\.\d/)) {
    print "OS = Linux 2.x.x\n" if $debug;
    $mail='/bin/mail';
    #$get_fs_cmd ="/bin/mount | grep '/dev' | cut -d' ' -f3";
    # <11>
    $get_fs_cmd ="/bin/mount |grep '/dev' |egrep -v 'type (shm|devpts|iso9660)' |cut -d' ' -f3";
    #$ifconfig_cmd ="/sbin/ifconfig -a  2>&1 | fgrep UP | fgrep -v lo0";
    #$ifconfig_list ="ifconfig -a|grep inet";
    $ifconfig_cmd ="/sbin/ifconfig -a 2>&1 | fgrep UP | fgrep -v LOOPBACK";
    $ifconfig_list ="/sbin/ifconfig -a|grep inet|grep -v '127\.0\.0\.1'";
}
elsif ($os_name = "HP-UX")  {
    print "OS = HP-UX\n" if $debug;
    $mail='/usr/bin/mailx';
    $get_fs_cmd ="/sbin/mount | egrep '/dev/vg00/|/dev/vx/dsk|/dev/vg2ufs|/dev/vg1ufs' | cut -d' ' -f1";
    ## TBD: detect main interface
    #$ifconfig_cmd ="/sbin/ifconfig lan0  2>&1 | fgrep UP | fgrep -v lo0";
    $ifconfig_cmd ="/sbin/ifconfig lan1  2>&1 | fgrep UP | fgrep -v lo0";
    $ifconfig_list ="lanscan|grep ETHER";
}
elsif (($os_name = "OpenBSD") && ($os =~ /^2\.\d/)) {
    print "OS = OpenBSD 2.x\n" if $debug;
    $mail='/usr/bin/mailx';
    $get_fs_cmd ="/sbin/mount | egrep '/dev' | cut -d' ' -f3";
    $ifconfig_cmd ="/sbin/ifconfig -a  2>&1 | fgrep UP | fgrep -v lo0";
    $ifconfig_list ="ifconfig -a|grep inet";
}
else {						# Unknown OS
    print "Operating system $os_name $os unknown, but lets have a go anyway!";
    $mail='/bin/mail';
    $get_fs_cmd ="/bin/mount | egrep '/dev' | cut -d' ' -f3";
    $ifconfig_cmd ="/sbin/ifconfig -a  2>&1 | fgrep UP | fgrep -v lo0";
    $ifconfig_list ="ifconfig -a|grep inet";
}

######### main ##################

&perror("Start: " . `date`);
# Document system name, IP and starting time:
#&perror(`uname -a; ifconfig -a|grep inet; date`);
#&perror(`uname -a; lanscan|grep ETHER; date`);
&perror(`uname -a; $ifconfig_list; date`);

# --- is ethernet/TR in promiscous mode? --
&check_network_interface();

## Single filesystem (as argument) or check all local filesystems?
if ( scalar(@ARGV) > 0 ) { # we have arguments
  $target=$ARGV[0];
  &perror("\n\nChecking only $target...\n");
  &find("$target")
}
else {
  if (length($exclude)) {  # <8>
    @filesys = `$get_fs_cmd | egrep -v "$exclude"`; # fill array with fs names
    chop(@filesys);
    #print("Analysing @filesys, excluding filesystems: $exclude, excluding directories: $exclude_dirs\n") if $debug;
    print("Analysing @filesys, excluding filesystems: $exclude, excluding directories: $exclude_dirs\n") if $debug;
    &perror("Analysing @filesys\n  excluding filesystems: $exclude \n  excluding directories: $exclude_dirs\n");
  } else {
    @filesys = `$get_fs_cmd`;                  # fill array with fs names
    chop(@filesys);
    print("Analysing @filesys, no exclusions\n") if $debug;
    &perror("Analysing @filesys, no exclusions\n");
  }

  if (! $group_rw) {
    &perror("Group writeable files are not analysed, group_rw is not set. \n");
  }

  while (@filesys) {
    ## Get $topdev, device name, for use in &wanted
    ($Main::topdev,$ino_1,$mode_1,$nlink_1,$uid_1,$gid_1) = 
       stat(@filesys[$#filesys]);
    print("Analysing @filesys[$#filesys]...\n") if $debug;
    &perror("Analysing @filesys[$#filesys]...\n");

    &find("@filesys[$#filesys]");		# see &wanted()
    #&find(\&wanted, "@filesys[$#filesys]");	# see &wanted()
    pop @filesys;
  }
}

&perror("Analysis done, now generate report: " . `date`);
&print_results;
&perror("\nDone: " . `date`);

### Mail results & clean temporary file
if ( -e $tmpfile ) {
    ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
       $atime,$mtime,$ctime,$blksize,$blocks) = stat("$tmpfile.Z");

    if ($size > 10000) {     # compress if bigger than 10k
      system "compress $tmpfile";
      ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
        $atime,$mtime,$ctime,$blksize,$blocks) = stat("$tmpfile.Z");
      if (($email_results) && ($size > 1500000)) {  #don't email if > 1.5MB
        $msg="The audit file was too big to send via Email, "
            .  "it is stored in $tmpfile.Z on $hostname. Please delete "
            .  "this file when you have uploaded it.";
        system "echo $msg |$mail -s '$hostname: $0 results' $user";
      }
      elsif ($email_results) {
          system "uuencode $tmpfile.Z $hostname.audit2.Z |$mail -s '$hostname: $0 results' $user";
      }
      else {        # Not emailing, just tell user where results are on stdout
        print "The script $0 has finished. Results are stored in $tmpfile.Z\n";
      }
    }
    elsif ($email_results) {
      system "$mail -s '$hostname: $0 results' $user <$tmpfile";
    }
    else {        # Not emailing, just tell user where results are on stdout
      print "The script $0 has finished. Results are stored in $tmpfile\n";
    }
    # Don't wipe, keep a trail
    #unlink $tmpfile;
}
else {
    print "No mail output! \n" if $debug;
}


exit;
# ------------- end of main -----------

# ------------- functions   -----------
sub print_results  {
  # <7>
  #if (@veryweird) {
    &perror("\n\n");
    &perror('>>>> ' . scalar($#veryweird+1) .' Difficult files containing <"> or <\\> or <$> in their name. These files have NOT been analysed in the categories below....');
    &perror("\n");
    foreach $f (@veryweird) { &perror("$f\n"); }
  #}
  #if (@weird) {
    &perror("\n>>>> " . scalar($#weird+1) ." strange or possible root kit files....\n");
    foreach $f (@weird) { 
      &perror("$f\n");
      &perror(`ls -ald "$f" 2>&1`); 
      #perror(`ls -ald "$f" `); 
    }
  #}
  #if (@config) {
    &perror("\n>>>> " . scalar($#config+1) ." config/possibly sensitive files....\n");
    #foreach $f (@config) { &perror(`ls -ald "$f" 2>&1`); }
    foreach $f (@config) { &perror(`ls -ald "$f"`); }
  #}
  #if (@trust) {
    &perror("\n>>>> " . scalar($#trust+1) ." trust files....\n");
    foreach $f (@trust) { 
      #perror(`ls -ald "$f" 2>&1`); 
      &perror(`ls -ald "$f"`); 
      @contents = `cat "$f"|egrep -v '^#' `; chop(@contents);
      &perror("contains: <@contents>\n");
      unlink("$f") if $aggressive;
    }
  #}
  #if (@suid) {
    &perror("\n>>>> " . scalar($#suid+1) ." suid files....\n");
    #foreach $f (@suid) { &perror(`ls -ald "$f" 2>&1`); }
    foreach $f (@suid) { &perror(`ls -ald "$f"`); }
  #}
  #if (@guid) {
    &perror("\n>>>> " . scalar($#guid+1) ."  sgid (only) group files....\n");
    foreach $f (@guid) { &perror(`ls -ald "$f"`); }
    #foreach $f (@guid) { &perror(`ls -ald "$f 2>&1"`); }
    #foreach $f (@guid) { &perror(`ls -ald "$f" 2>&1`); }
  #}

  #if (@worldwrite) {
    &perror("\n>>>> " . scalar($#worldwrite+1) ." World writeable files....\n");
    foreach $f (@worldwrite) {
      #print "$f \n";
      &perror(`ls -ald "$f" 2>&1`);
    }
  #}
  if ($group_rw) {
    &perror("\n>>>> " . scalar($#groupwrite+1) ." groupwriteable files....\n");
    foreach $f (@groupwrite) { &perror(`ls -ald "$f" 2>&1`); }
  }
}

sub wanted {					# called by &find()
    # $dir= path  $_= filename $name= $dir/$_
    ($dev,$ino,$mode,$nlink,$uid,$gid) = stat($_);

    ## Check if the current file is on a device other that the
    ## the original filesystem, i.e. if a FS is mounted below
    ## another, we need to detect this and stop searching.
    ## By setting $prune=1, the &find function should stop
    ## descending the tree ion question.
    ## Notes: On Solaris this seems to work fine (e.g. searching root
    ## is fast). On HP, it seemed to ignore the prune and continue
    ## descending all trees in root.
    #$prune=1 if ($dev != topdev);
    if (($dev != 0) && ($dev != $Main::topdev)) {
      $prune=1; $Main::prune=1;
      # If $prune is set to 1 ==> the search tree is to be pruned
      print "Prune: Topdev=$Main::topdev, dev=$dev leaving $_\n" if $debug;
      return;
    }

    ## very weird files <##>
    #if (/\\|\"|\$/) {  # we can't even do an ls on these files
    if (/\\|\"/) {  # we can't even do an ls on these files
        push @veryweird,"$name";
    }
    elsif (readlink($name)) {
        next;                      # ignore symbolic links
    }
    elsif (/$exclude_dirs/) {
        print "Ignore directory: $_\n" if $debug;
        next;                      # ignore specific files/dirs
    }
    else {
      if (/$weirds/) {  # potentially dangerous
        push @weird,"$name";
	#unlink("$name") if $aggressive;
	`mv $name $dir/STRANGE.$_` if $aggressive;
      }
      elsif (/$configs/) {	
        push @config,$name;
      }
      elsif (/$trusts/) {			# trusts
        push @trust,$name;
    	#unlink("$name") if $aggressive; 
	`mv $name $dir/STRANGE.$_` if $aggressive;
      }

      # Check for SUID, check for GID if not already SUID <3>
      # and if it's a file (we don't care about suid directories)
      if    (-u $_)              { push @suid,$name; }
      elsif ((-g $_) && (-f $_)) { push @guid,$name; }
      #push @suid,$name if (-u $_);
      #push @guid,$name if (-g $_);
     
      # Check for world write, and group write if not world write <3>
      # see mknod(2) for description of $mode
      if    ($mode & 002)  { 
         # avoid worldwrite devices; check for file or dir
	 push @worldwrite,$name if ((-f $_) || (-d $_)); 
         #push @worldwrite,$name; 
      }
      elsif ( ($mode & 020) && ($group_rw) ){ 
         # avoid groupwriteable devices; check for file or dir
	 ##push @groupwrite,$name if ((-f $_) || (-d $_)); 
      }
      #push @worldwrite,$name if ($mode & 002);
      #push @groupwrite,$name if ($mode & 020);
    }
}


sub check_network_interface {
    @result = `$ifconfig_cmd`;
    if ($result[0] =~ /PROMISC/) {
	# Note that most OS won't report promis. mode with ifconfig
	&perror("WARNING! network interface is promiscous:\n@result");
    }
    if (@result > 1) {
	## Example: some hosts are allowed several interfaces
	if ($hostname !~ /$multiple_interfaces_ok/) {
	    &perror("WARNING! more than one network interface is "
		   ."active:\n@result");
	}
    }
}

sub perror {
    open(OUT, ">>$tmpfile") || die "Cannot append tmp file $tmpfile.\n";
    print OUT @_;
    print @_ if $debug2;
    close(OUT);
}



#!/bin/sh
#                                       Sean Boran 18.Jun.03
# /secure/audit.sh
#
# FUNCTION: Call two main audit scripts: audit1.sh and audit2.pl
#           and collate results.
# USAGE:
#           sh ./audit.sh
###############################################################

hostname=`uname -n`
dir=`dirname $0`;

PATH=${PATH}:/usr/proc/bin; export PATH

#target=/tmp
target=.
cd $target

echo "Run audit part 1, results in $target/$hostname.audit1.log..."
sh $dir/audit1.sh > $hostname.audit1.$$.log 2>&1 
echo "Run audit part 2..."
perl $dir/audit2.pl

echo "Create one gzipped tarball from .."
ls -al $hostname.audit[12]*log
tar cf - $hostname.audit[12]*log | gzip > audit.$hostname.tgz
if [ $? -eq 0 ] ; then
  echo "Deleting temporary audit files .."
  #rm  $target/$hostname.audit[12]*log
fi

ls -l $target/audit.$hostname.tgz
echo "finished"


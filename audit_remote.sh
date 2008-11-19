#!/bin/sh
#
# audit_remote.sh
# Connect to a list of if machines, download the audit scripts,
# run then, compress results and upload them.
#
# - Adapt the server list "server1 server2" etc. below
# - you'll need an SSH trust ot target systems
# - delete the "sudo" if not needed

dir1="/tmp/aud";

for h in server1 server3 server3; do

  echo "Connecting to $h `date`"
  ssh $h "mkdir $dir1 2>/dev/null; chmod 700 $dir1"
  scp -q audit.sh audit1.sh audit2.pl $h:/$dir1
  echo "Run audit `date` on $h"
  ssh $h "PATH=${PATH}:/bin/:/usr/local/bin; cd $dir1; nice sudo ./audit.sh"
  scp -q "$h":"$dir1"/"*.tgz" .

done
echo "Finished `date`"


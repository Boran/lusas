# Introduction #

```
./lusas-basic.sh -h

lusas-basic: 
Linux/unix security auditing scripts.

OPTIONS:
   -h	Show this message
   -d	email or emails where to send the results. i.e.: a@example.com,b@example.com,root
   -e	Extended.  Collect a copy of files
   -s	Verify package checksums
   -l	Don't clean up after run. Leave the directory with the results on disk.
   -c	Cleanup after run, leave nothing behind.

	If neither -l or -c are not set a .tar.gz file with the result will be left on disk.

```

# Details #

For the other audit scripts, refer to http://boran.com/audit
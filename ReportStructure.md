# Introduction #

With a structured test base, the challenge is to analyze the compiled data.  Some of this can be automated and some must be done by hand, the general idea is to make it as easy as possible.  After the fact the directory should be tared and compressed (using gzip or


# Details #

Making one giant file makes the results hard to read, I propose the following structure based on the tests:

Create a directory with the following naming format:  hostname-YYYYMMDD-HHMM

In the directory create the following files and directories:
  * lusas-basic.log: With the basic log, this includes the test from sections 1-4
  * services: directory which contains a subdirectory for each service
  * service-dir:
    * lusas-<service name>.log: main logfile
    * copy of the recompiled information: config files, test results, etc
  * software.log: file with the output of the install packages
  * patches.log: patchlevel information
  * patches-pending.log: shows a list of the patches pending to be installed (if possible to generate  locally)
  * logs: directory that contains log information
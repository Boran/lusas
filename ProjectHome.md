This is a collection of command line security auditing scripts for Linux/Unix.
Originally by Sean Boran in 2000, with a few improvements over the years.

Auditing the security of an existing system can be time-consuming, and often requires on-site visits. There are several commercial tools and a few free ones that help, but they can be complicated and require local compilation or configuration.

So a tool was developed with the following aims:
  * Simple to use: the auditor could even give the tool to the sysadmin, ask him to run it at night and send the results back to the auditor (perhaps by encrypted email).
  * For situations where a "quick audit" of the system is required.
  * Easy to verify: it is not as thorough as other tools, but it is small and easy to understand.
  * Does not require a compiler or other tools.
  * Support several Linux and Unix derivatives

This script automates the gathering of the information only. Of course, the difficult part is the interpretation of results and deciding what countermeasures to take.

Please visit http://code.google.com/p/lusas for the current documentation.
The previous doc is on http://boran.com/audit

DOWNLOAD: The sources are available via SVN on Google code.
USAGE:
> ./lusas-basic.sh -h
> For the other audit scripts, refer to http://boran.com/audit

Update dec'08: Pablo is working on a new release replacing audit1.sh with lusas-basic.sh. Checkout his design in the wiki and provide feedback via the issue queue.
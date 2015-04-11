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


static Elf64_Dyn *null1;
static Elf64_Dyn *null2;
static Elf64_Dyn *libc;

/*
 * I hate using magic values -- this feels beyond hacky.
 *
 * I think that parse_rela should not be split up - the documentation that I've read does not help
 * add clarity to either r_info field whether it be ELF64_R_TYPE, ELF64_R_SYM, or any of the remaining Elf64_Rela fields actually.
 *		The only (half decent) documentation I've been able to find is from oracle and applies only to SPARC as far as I can tell. (not mad at all :^) )
 *
 * these defines will help later when adding robustness to hook_[addend, symortype, more relocations that aren't documented well]();
 */
#define RELOC_ADDEND 1
#define RELOC_INFO 2

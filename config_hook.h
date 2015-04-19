FILE *my_fopen(char *filename, char *mode);

FILE *(*ref_fopen)(char*, char*);

Elf64_Rela *ref_fopen_Rela;

int _APPEND_work(char **__new, int *_buf_len, char *filename, char *append);
int _EXPLICIT_work(char **__new, char *config_name, char *redefine, char *old, char **buf, int *_buf_len);


enum worktype {
	APPEND,
	EXPLICIT,
	NOWORK
};


#define RELOC_ADDEND 1
#define RELOC_INFO 2

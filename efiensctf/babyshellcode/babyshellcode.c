#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

char shellcode[] = { 0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 
					0x2f, 0x2f, 0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 
					0x68, 0x72, 0x69, 0x01, 0x01, 0x81, 0x34, 0x24,
					0x01, 0x01, 0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a,
					0x08, 0x5e, 0x48, 0x01, 0xe6, 0x56, 0x48, 0x89,
					0xe6, 0x31, 0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05 };

int main ()
{
	setvbuf (stdin, 0, _IONBF, 0);
	setvbuf (stdout, 0, _IONBF, 0);
	setvbuf (stderr, 0, _IONBF, 0);


	char *a = mmap (NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	memcpy (a+16, shellcode, 8*6);

	printf ("%p\n", a);



	puts ("Send me your shellcode");
	fgets (a, 9, stdin);

	((void (*)(void))a) ();
	return 0;
}

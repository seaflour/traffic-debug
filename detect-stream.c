#include "detect-stream.h"

int dns_lookup_youtube(char *addr) {
	FILE *fp;
	char command[1024];
	char buffer[1024];

	/* create command string */
	sprintf(command, "host %s | cut -d' ' -f5", addr);
	/* execute command and open for reading */
	fp = popen(command,"r");

	if (fp == NULL) {
		return 0;
	}

	/* read the output of the command */
	fgets(buffer, sizeof(buffer)-1, fp);

	pclose(fp);

	return strcmp(buffer,"cache.google.com.\n");
}

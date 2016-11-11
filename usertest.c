#include "usertest.h"

#define ANSI_YELLOW	"\x1b[33m"
#define ANSI_RESET	"\x1b[0m"

void *inputTime(void *argp) {
	char c;
	struct timeval t;
	struct tm *ts;
	char buffer[80];

	printf("Press any key to indicate a playback error.\nPress enter when finished.\n\n");

	while (c = getchar() != '\n') {
		gettimeofday(&t, NULL);
		ts = localtime(&(t.tv_sec));
		strftime(buffer, 80, "%H:%M:%S", ts);
		printf(ANSI_YELLOW "Input at: " ANSI_RESET "%s\n", buffer);
	}

	printf("usertest over\n");
	return NULL;
}

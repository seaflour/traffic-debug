#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <curses.h>

#define ANSI_YELLOW	"\x1b[33m"
#define ANSI_RESET	"\x1b[0m"

int main(int argc, char **argv) {
	int c;
	struct timeval t;
	struct tm *ts;
	char buffer[80];

	initscr();
	cbreak();
	noecho();
	printw("Press any key to indicate an error.\nPress enter when finished.\n\n");
	refresh();

	while (1) {
		c = getch();
		if (c != (int)'\n') {
			gettimeofday(&t, NULL);
			ts = localtime(&(t.tv_sec));
			strftime(buffer, 80, "%H:%M:%S", ts);
			printw("Input at: %s\n", buffer);
			refresh();
		}
		else break;
	}
	
	printw("\n\nFinished. Press any key to exit.");
	getch();
	refresh();
	endwin();

	printf("usertest over\n");
	return 0;
}

/*#include "usertest.h"

#define ANSI_YELLOW	"\x1b[33m"
#define ANSI_RESET	"\x1b[0m"

void *inputTime(void *argp) {
	int c;
	struct timeval t;
	struct tm *ts;
	char buffer[80];

	initscr();
	cbreak();
	noecho();
	printf("Press any key to indicate a playback error.\nPress enter when finished.\n\n");
	refresh();

	while (1) {
		c = getch();
		if (c != (int)'\n') {
			gettimeofday(&t, NULL);
			ts = localtime(&(t.tv_sec));
			strftime(buffer, 80, "%H:%M:%S", ts);
			printf(ANSI_YELLOW "Input at: " ANSI_RESET "%s\n", buffer);
			refresh();
		}
		else break;
	}
	endwin();

	printf("usertest over\n");
	return NULL;
}*/

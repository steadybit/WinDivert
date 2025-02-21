#pragma once
#include <cargs.h>
#define CLI_OPTS_DURATION_SET (1 << 0)
#define CLI_OPTS_TIME_SET (1 << 1)

typedef struct cli_opts {
	const char* filter;
	const char* mode;
	unsigned int time; // [MODE: delay] - Amount of time each packet is going to be delayed.
	bool jitter; // [MODE: delay] - Adds a +-30% jitter to each packet.
	unsigned int duration; // Amount of time the attack is going to run.
	unsigned int flags;
} CLI_OPTS;

void InitCLIOpts(CLI_OPTS* opts);
int ParseCLIOpts(CLI_OPTS* opts, int argc, char **argv);
void PrintCLIOpts(CLI_OPTS* opts);

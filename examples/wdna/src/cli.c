#include <cli.h>

static struct cag_option options[] = {
    {.identifier = 'f',
    .access_letters = "f",
    .access_name = "file",
    .value_name = "FILE",
    .description = "WinDivert filter file"},
    {.identifier = 'm',
    .access_letters = "m",
    .access_name = "mode",
    .value_name = "MODE",
    .description = "One of the three modes: drop|delay|corrupt."},
    {.identifier = 'j',
    .access_letters = "j",
    .access_name = "jitter",
    .value_name = "JITTER",
    .description = "[MODE:delay] - random +-30% jitter to network delay."},
    {.identifier = 't',
    .access_letters = "t",
    .access_name = "time",
    .value_name = "TIME",
    .description = "[MODE:delay] - how much should traffic be delayed in 'ms'."},
	 {.identifier = 'h',
	.access_letters = "h",
	.access_name = "help",
	.description = "Shows all options."},
    {.identifier = 'd',
    .access_letters = "d",
    .access_name = "duration",
    .value_name = "DURATION",
    .description = "Amount of time the attack is going to run in 's'."},
    {.identifier = 'p',
    .access_letters = "p",
    .access_name = "percentage",
    .value_name = "PERCENTAGE",
    .description = "[MODE:drop] - percentage of packets to drop. [MODE:corrupt] - percentage of packets to corrupt."},
};


void InitCLIOpts(CLI_OPTS* opts) {
    opts->file = NULL;
    opts->mode = NULL;
    opts->duration = 0;
    opts->jitter = false;
    opts->time = 0;
    opts->flags = 0;
}

char* boolToString(bool conv) {
    if (conv) {
        return "Yes";
    }
    else {
        return "No";
    }
}

void PrintCLIOpts(CLI_OPTS* opts) {
    printf("File: '%s'\n", opts->file);
    printf("Duration: '%d s'\n", opts->duration);
    printf("Mode: '%s'\n", opts->mode);

    if (strcmp(opts->mode, "delay") == 0) {
		printf("Delay time: '%d ms'\n", opts->time);
		printf("Jitter: '%s'\n", boolToString(opts->jitter));
    }

    if (strcmp(opts->mode, "corrupt") == 0) {
        printf("Corrupt percentage: '%d'\n", opts->percentage);
    }

    if (strcmp(opts->mode, "drop") == 0) {
        printf("Drop percentage: '%d'\n", opts->percentage);
    }
}

int ParseCLIOpts(CLI_OPTS* opts, int argc, char **argv) {
    unsigned int delay_time;
    cag_option_context context;
    cag_option_init(&context, options, CAG_ARRAY_SIZE(options), argc, argv);
    while (cag_option_fetch(&context)) {
        switch (cag_option_get_identifier(&context)) {
        case 'f': {
            opts->file = cag_option_get_value(&context);
            break;
        }
        case 'm': {
            opts->mode = cag_option_get_value(&context);
            if (strcmp("drop", opts->mode) != 0 && strcmp("delay", opts->mode) != 0 && strcmp("corrupt", opts->mode) != 0) {
                printf("Invalid mode '%s'. Allowed modes are: 'drop', 'delay', 'corrupt'.\n", opts->mode);
                return 1;
            }
            break;
        }
        case 'd': {
            const char* duration_str = cag_option_get_value(&context);
            opts->duration = strtoul(duration_str, NULL, 10);
            if (errno != 0) {
                printf("Invalid duration: '%s'.\n", duration_str);
                return 1;
            }

            if (opts->duration == 0) {
                printf("Invalid delay time: '%s'.\n", duration_str);
                return 1;
            }
            opts->flags |= CLI_OPTS_DURATION_SET;
            break;
        }
        case 't': {
			const char* delay_time_str = NULL;
            delay_time_str = cag_option_get_value(&context);
            opts->time = strtoul(delay_time_str, NULL, 10);
            if (errno != 0) {
                printf("Invalid delay time: '%s'.\n", delay_time_str);
                return 1;
            }

            if (opts->time == 0) {
                printf("Invalid delay time: '%s'.\n", delay_time_str);
                return 1;
            }
            opts->flags |= CLI_OPTS_TIME_SET;
            break;
        }

        case 'j': {
            opts->jitter = true;
            break;
        }

        case 'p': {
            const char* percentage_str = NULL;
            percentage_str = cag_option_get_value(&context);
            opts->percentage= strtoul(percentage_str, NULL, 10);
            if (errno != 0) {
                printf("Invalid percentage amount: '%s'.\n", percentage_str);
                return 1;
            }
            if (opts->percentage == 0 || opts->percentage> 100) {
                printf("Invalid delay time: '%s'.\n", percentage_str);
                return 1;
            }

            opts->flags |= CLI_OPTS_PERCETAGE_SET;
            break;
        }

        case 'h':
            cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
            return 2;
        }
    }

    if (opts->file == NULL) {
        printf("File must not be empty.");
        return 1;
    }

    if (opts->mode == NULL) {
        printf("Mode must not be empty.");
        return 1;
    }

    if (!(opts->flags & CLI_OPTS_DURATION_SET)) {
        printf("Duration of an attack must not be empty.");
        return 1;
    }

    if (strcmp("delay", opts->mode) == 0 && !(opts->flags & CLI_OPTS_TIME_SET)) {
        printf("Delay time must not be empty in delay mode.");
        return 1;
    }

    if (strcmp("drop", opts->mode) == 0 && !(opts->flags & CLI_OPTS_PERCETAGE_SET)) {
        printf("Drop percentage must not be empty in drop mode.");
        return 1;
    }

    if (strcmp("corrupt", opts->mode) == 0 && !(opts->flags & CLI_OPTS_PERCETAGE_SET)) {
        printf("Corrupt percentage must not be empty in corrupt mode.");
        return 1;
    }

    return 0;
}



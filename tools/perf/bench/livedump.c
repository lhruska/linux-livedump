/*
 *
 * livedump.c
 *
 * livedump: Benchmark for livedump performance
 */
#include "../perf.h"
#include "../util/util.h"
#include <subcmd/parse-options.h>
#include "../builtin.h"
#include "bench.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define	LIVEDUMP_STATE_UNKNOWN	'0'
#define	LIVEDUMP_STATE_INIT		'1'
#define	LIVEDUMP_STATE_START	'2'
#define	LIVEDUMP_STATE_UNINIT	'5'
#define	LIVEDUMP_TYPE_SM		'0'
#define	LIVEDUMP_TYPE_INT		'1'

#define	LIVEDUMP_SYSFS_STATE	"/sys/kernel/livedump/state"
#define	LIVEDUMP_SYSFS_USE_INT	"/sys/kernel/livedump/use_interrupt"
#define	LIVEDUMP_SYSFS_OUTPUT	"/sys/kernel/livedump/output"

#define LOOPS_DEFAULT 100
static int loops = LOOPS_DEFAULT;
static const char *device;

static const struct option options[] = {
	OPT_INTEGER('l', "loop", &loops, "Specify number of loops"),
	OPT_STRING('d', "device", &device, "device name",
		"Specify output device path"),
	OPT_END()
};

static const char * const bench_livedump_usage[] = {
	"perf bench livedump <options>",
	NULL
};

static int bench_livedump_setup(bool interrupt)
{
	char val, curr_state;
	int fd;
	size_t len;
	ssize_t write_len, read_len;
	char output_val[256];

	/* unint */
	val = LIVEDUMP_STATE_UNINIT;
	fd = open(LIVEDUMP_SYSFS_STATE, O_RDWR);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'state' sysfs entry: %s\n",
			strerror(errno));
		return -errno;
	}

	read_len = read(fd, &curr_state, 1);
	if (read_len == -1) {
		fprintf(stderr, "Unable to read from 'state' sysfs entry: %s\n",
			strerror(errno));
		close(fd);
		return -EINVAL;
	}

	if (curr_state != LIVEDUMP_STATE_UNKNOWN &&
		curr_state != LIVEDUMP_STATE_UNINIT) {
		write_len = write(fd, &val, 1);
		if (write_len == -1) {
			fprintf(stderr, "Unable to write into 'state' sysfs entry: %s\n",
				strerror(errno));
			close(fd);
			return -EINVAL;
		}
	}

	close(fd);

	/* set device path */
	fd = open(LIVEDUMP_SYSFS_OUTPUT, O_WRONLY);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'output' sysfs entry: %s\n",
			strerror(errno));
		return -errno;
	}

	len = strlen(device);

	write_len = write(fd, device, len);
	if (write_len == -1) {
		fprintf(stderr, "Unable to write into 'state' sysfs entry: %s\n",
			strerror(errno));
		close(fd);
		return -EINVAL;
	}

	close(fd);
	fd = open(LIVEDUMP_SYSFS_OUTPUT, O_RDONLY);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'output' sysfs entry: %s\n",
				strerror(errno));
		return -errno;
	}

	read_len = read(fd, output_val, len);
	if (read_len == -1) {
		fprintf(stderr, "Unable to read from 'state' sysfs entry: %s\n",
				strerror(errno));
		close(fd);
		return -EINVAL;
	}

	close(fd);

	if (strncmp(device, output_val, len) != 0) {
		fprintf(stderr,
				"Unable to write the device path into 'output' sysfs entry\n");
		return -EFAULT;
	}

	/* type */
	if (interrupt)
		val = LIVEDUMP_TYPE_INT;
	else
		val = LIVEDUMP_TYPE_SM;

	fd = open(LIVEDUMP_SYSFS_USE_INT, O_WRONLY);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'type' sysfs entry: %s\n",
				strerror(errno));
		return -errno;
	}

	write_len = write(fd, &val, 1);
	if (write_len == -1) {
		fprintf(stderr, "Unable to write into 'use_interrupt' sysfs entry: %s\n",
				strerror(errno));
		close(fd);
		return -EINVAL;
	}

	close(fd);

	return 0;
}

static int bench_livedump_get_state(char *val)
{
	int fd;
	ssize_t read_len;

	fd = open(LIVEDUMP_SYSFS_STATE, O_RDONLY);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'state' sysfs entry: %s\n",
				strerror(errno));
		return -errno;
	}

	read_len = read(fd, val, 1);
	if (read_len == -1) {
		fprintf(stderr, "Unable to read from 'state' sysfs entry: %s\n",
				strerror(errno));
		close(fd);
		return -EINVAL;
	}

	return 0;
}

static int bench_livedump_init(void)
{
	int fd, ret;
	char val;
	ssize_t write_len;

	val = LIVEDUMP_STATE_INIT;
	fd = open(LIVEDUMP_SYSFS_STATE, O_WRONLY);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'state' sysfs entry: %s\n",
				strerror(errno));
		return -errno;
	}

	write_len = write(fd, &val, 1);
	if (write_len == -1) {
		fprintf(stderr, "Unable to write into 'state' sysfs entry: %s\n",
				strerror(errno));
		close(fd);
		return -EINVAL;
	}

	close(fd);

	ret = bench_livedump_get_state(&val);

	if (ret != 0 || val != LIVEDUMP_STATE_INIT) {
		fprintf(stderr, "Unable to change state of livedump.\n");
		return -EINVAL;
	}

	return 0;
}

static int bench_livedump_uninit(void)
{
	int fd, ret;
	char val;
	ssize_t write_len;

	val = LIVEDUMP_STATE_UNINIT;
	fd = open(LIVEDUMP_SYSFS_STATE, O_WRONLY);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'state' sysfs entry: %s\n",
				strerror(errno));
		return -errno;
	}

	write_len = write(fd, &val, 1);
	if (write_len == -1) {
		fprintf(stderr, "Unable to write into 'state' sysfs entry: %s\n",
				strerror(errno));
		close(fd);
		return -EINVAL;
	}

	close(fd);

	ret = bench_livedump_get_state(&val);

	if (ret != 0 || val != LIVEDUMP_STATE_UNINIT) {
		fprintf(stderr, "Unable to change state of livedump.\n");
		return -EINVAL;
	}

	return 0;
}

static int bench_livedump_start(void)
{
	int fd;
	char val, ret;
	ssize_t write_len;

	val = LIVEDUMP_STATE_START;
	fd = open(LIVEDUMP_SYSFS_STATE, O_WRONLY);

	if (fd == -1) {
		fprintf(stderr, "Unable to open 'state' sysfs entry: %s\n",
				strerror(errno));
		return -errno;
	}

	write_len = write(fd, &val, 1);
	if (write_len == -1) {
		fprintf(stderr, "Unable to write into 'state' sysfs entry: %s\n",
				strerror(errno));
		close(fd);
		return -EINVAL;
	}

	close(fd);

	ret = bench_livedump_get_state(&val);

	if (ret != 0 || val != LIVEDUMP_STATE_START) {
		fprintf(stderr, "Unable to change state of livedump.\n");
		return -EINVAL;
	}

	return 0;
}

static int bench_livedump_common(int argc, const char **argv, bool interrupt)
{
	struct timeval start, stop, diff;
	unsigned long long result_usec = 0;
	const char *name = NULL;
	int i, ret;

	argc = parse_options(argc, argv, options, bench_livedump_usage, 0);

	if (!device) {
		fprintf(stderr, "Missing required argument: device must be specified.\n");
		exit(1);
	}

	ret = bench_livedump_setup(interrupt);
	if (ret) {
		fprintf(stderr, "Runtime error: Setup phase failed.\n");
		exit(1);
	}

	for (i = 0; i < loops; ++i) {
		ret = bench_livedump_init();
		if (ret) {
			fprintf(stderr, "Runtime error: Init phase failed.\n");
			exit(1);
		}

		gettimeofday(&start, NULL);

		ret = bench_livedump_start();
		if (ret) {
			fprintf(stderr, "Runtime error: Starting phase failed.\n");
			exit(1);
		}

		gettimeofday(&stop, NULL);

		ret = bench_livedump_uninit();
		if (ret) {
			fprintf(stderr, "Runtime error: Uninit phase failed.\n");
			exit(1);
		}

		timersub(&stop, &start, &diff);

		result_usec = diff.tv_sec * 1000000;
		result_usec += diff.tv_usec;
	}

	if (interrupt)
		name = "interrupted livedump";
	else
		name = "stop-machine state livedump";

	switch (bench_format) {
	case BENCH_FORMAT_DEFAULT:
	printf("# Executed %'d %ss\n", loops, name);
	printf(" %14s: %lu.%03lu [sec]\n\n", "Total time",
		(unsigned long) (result_usec / 1000000),
		(unsigned long) (result_usec / 1000));

	printf(" %14lf usecs/op\n",
		(double)result_usec / (double)loops);
	printf(" %'14d ops/sec\n",
		(int)((double)loops /
		((double)result_usec / (double)1000000)));
	break;

	case BENCH_FORMAT_SIMPLE:
	printf("%lu.%03lu\n",
		(unsigned long) (result_usec / 1000000),
		(unsigned long) (result_usec / 1000));
	break;

	default:
	fprintf(stderr, "Unknown format:%d\n", bench_format);
	exit(1);
	break;
	}

	return 0;
}

int bench_livedump_sm(int argc, const char **argv)
{
	return bench_livedump_common(argc, argv, 0);
}

int bench_livedump_int(int argc, const char **argv)
{
	return bench_livedump_common(argc, argv, 1);
}

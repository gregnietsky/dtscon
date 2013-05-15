#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>
#include <ctype.h>
#include <grp.h>

extern int is_file(const char *path) {
	struct stat sr;
	if (!stat(path, &sr)) {
		return 1;
	} else {
		return 0;
	}
}

extern int is_dir(const char *path) {
	struct stat sr;
	if (!stat(path, &sr) && S_ISDIR(sr.st_mode)) {
		return 1;
	} else {
		return 0;
	}
}

extern int is_exec(const char *path) {
	struct stat sr;
	if (!stat(path, &sr) && (S_IXUSR & sr.st_mode)) {
		return 1;
	} else {
		return 0;
	}
}

extern int mk_dir(const char *dir, mode_t mode, uid_t user, gid_t group) {
	struct stat sr;

	if ((stat(dir, &sr) && (errno == ENOENT)) && !mkdir(dir, mode) && !chown(dir, user, group)) {
		return 0;
	}
	return -1;
}

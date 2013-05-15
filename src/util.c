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

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "dtscon.h"
#include <framework.h>

extern void touch(const char *filename, uid_t user, gid_t group) {
	int fd;

	fd = creat(filename, 0600);
	close(fd);
	chown(filename, user, group);
}

extern char *b64enc_buf(const char *message, uint32_t len, int nonl) {
	BIO *bmem, *b64;
	BUF_MEM *ptr;
	char *buffer;
	double encodedSize;

	encodedSize = 1.36*len;
	buffer = objalloc(encodedSize+1, NULL);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	if (nonl) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	BIO_write(b64, message, len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &ptr);

	buffer = objalloc(ptr->length+1, NULL);
	memcpy(buffer, ptr->data, ptr->length);


	BIO_free_all(b64);

	return buffer;
}

extern char *b64enc(const char *message, int nonl) {
	return b64enc_buf(message, strlen(message), nonl);
}

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

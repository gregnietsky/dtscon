#include <curl/curl.h>

#include <framework.h>

struct curl {
	CURL *easy_handle;
} *curl_easy_handle;

void curl_unref(void *data) {
	struct curl *curl = data;
	curl_easy_cleanup(curl->easy_handle);
}

extern void init_curleasy() {
	if (!curl_easy_handle) {
		curl_easy_handle = objalloc(sizeof(*curl_easy_handle), curl_unref);
		curl_easy_handle->easy_handle = curl_easy_init();
	} else {
		objref(curl_easy_handle);
	}
}

extern void close_curleasy() {
	objunref(curl_easy_handle);
}

extern char *url_escape(char *url) {
	char *esc;
	objlock(curl_easy_handle);
	esc = curl_easy_escape(curl_easy_handle->easy_handle, url, 0);
	objunlock(curl_easy_handle);
	return esc; 
}

extern char *url_unescape(char *url) {
	char *uesc;
	objlock(curl_easy_handle);
	uesc = curl_easy_unescape(curl_easy_handle->easy_handle, url, 0, 0);
	objunlock(curl_easy_handle);
	return uesc;
}

extern void free_curl(void *curlvar) {
	if (curlvar) {
		curl_free(curlvar);
	}
}

#include <string.h>

#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>

#include <framework.h>

#include "dtscon.h"

struct xslt_doc {
	xsltStylesheetPtr doc;
	struct bucket_list *params;
};

struct xslt_param {
	const char *name;
	const char *value;
};

void free_xsltdoc(void *data) {
	struct xslt_doc *xsltdoc = data;

	xsltFreeStylesheet(xsltdoc->doc);
	objunref(xsltdoc->params);
	xslt_close();
}

static void *xslt_has_init_parser = NULL;

void free_parser(void *data) {
	xsltCleanupGlobals();
	xmlCleanupParser();
}

int xslt_hash(const void *data, int key) {
	int ret;   
	const struct xslt_param *xp = data;
	const char* hashkey = (key) ? data : xp->name;

	if (hashkey) {
		ret = jenhash(hashkey, strlen(hashkey), 0);
	} else {
		ret = jenhash(xp, sizeof(xp), 0);
	}
	return(ret);
}

extern struct xslt_doc *xslt_create(struct xml_doc *xmldoc, const char *xsltfile, param_callback paramcb) {
	struct xslt_doc *xsltdoc;

	if (!(xsltdoc = objalloc(sizeof(*xsltdoc), free_xsltdoc))) {
		return NULL;
	}
	xslt_init();

	xsltdoc->doc = xsltParseStylesheetFile((const xmlChar*)xsltfile);
	xsltdoc->params = create_bucketlist(0, xslt_hash);
	return xsltdoc;
}

void free_param(void *data) {
	struct xslt_param *param = data;	
	if (param->name) {
		free((void*)param->name);
	}
	if (param->value) {
		free((void*)param->value);
	}
}

extern void xslt_addparam(struct xslt_doc *xsltdoc, const char *param, const char *value) {
	struct xslt_param *xparam;
	int size;

	if (!xsltdoc || !xsltdoc->params || !objref(xsltdoc) || !(xparam = objalloc(sizeof(*xparam), free_param))) {
		return;
	}

	size = strlen(value) + 3;
	ALLOC_CONST(xparam->name, param);
	xparam->value = malloc(size);
	snprintf((char *)xparam->value, size, "'%s'", value);
	addtobucket(xsltdoc->params, xparam);
	objunref(xparam);
	objunref(xsltdoc);
}

extern void xslt_clearparam(struct xslt_doc *xsltdoc) {
	if (!xsltdoc || !xsltdoc->params) {
		return;
	}

	objunref(xsltdoc->params);
	xsltdoc->params = create_bucketlist(0, xslt_hash);
}

extern void xslt_apply(struct xml_doc *xmldoc, struct xslt_doc *xsltdoc, const char *filename, int comp) {
	const char **params = NULL;
	struct xslt_param *xparam;
	struct bucket_loop *bloop;
	xmlDocPtr res, doc;
	int cnt=0;

	if (!(doc = xml_getDocPtr(xmldoc))) {
		return;
	}

	if (!objref(xsltdoc)) {
		objunref(xsltdoc);
		return;
	}

	params = malloc(sizeof(void*) * (bucket_list_cnt(xsltdoc->params)*2 + 2));
	bloop = init_bucket_loop(xsltdoc->params);
	while(bloop && (xparam = next_bucket_loop(bloop))) {
		params[cnt] = xparam->name;
		cnt++;
		params[cnt] = xparam->value;
		cnt++;
		objunref(xparam);
	};
	params[cnt] = NULL;
	res = xsltApplyStylesheet(xsltdoc->doc, doc, params);

	touch(filename, 80, 80);
	xsltSaveResultToFilename(filename, res, xsltdoc->doc, comp);

	free(params);
	xslt_clearparam(xsltdoc);
	xmlFreeDoc(res);
	objunref(xmldoc);
	objunref(xsltdoc);
}

extern void xslt_init() {
	if (!xslt_has_init_parser) {
		xslt_has_init_parser=objalloc(0, free_parser);
	} else {
		objref(xslt_has_init_parser);
	}
}

extern void xslt_close() {
	if (xslt_has_init_parser) {
		objunref(xslt_has_init_parser);
	}
}

#include <string.h>
#include <newt.h>
#include <stdlib.h>
#include "dtscon.h"

struct form_box {
	newtComponent form;
	int	width;
	int	height;
	int	row;
	struct bucket_list *results;
	const char* title;
	int	flags;
	struct xml_search *xsearch;
	const char* attrkey;
	const char* xpath;
	struct xml_doc *xmldoc;
};

enum restype {
	NEWT_FORM_ENTRYBOX,
	NEWT_FORM_CHECKBOX
};

struct form_result {
	const char *name;
	const char *keyval;
	union {
		char *entry;
		char check;
	} value;
	struct xml_node *node;
	enum restype  type;
};

int results_hash(const void *data, int key) {
	int ret = 0;
	const struct form_result *fr = data;
	const char* hashkey = (key) ? data : fr->name;

	if (hashkey) {
		ret = jenhash(hashkey, strlen(hashkey), 0);
	}
	return(ret);
}

static void free_result(void *data) {
	struct form_result *fr = data;
	if (fr->name) {
		free((char*)fr->name);
	}
	if (fr->keyval) {
		free((char*)fr->keyval);
	}
	if (fr->node) {
		objunref(fr->node);
	}
}

static void free_form(void *data) {
	struct form_box *fb = data;
	objunref(fb->results);
	objunref(fb->xsearch);
	if (fb->title) {
		free((char *)fb->title);
	}
	if (fb->attrkey) {
		free((char *)fb->attrkey);
	}
	if (fb->xpath) {
		free((char *)fb->xpath);
	}
	if (fb->xmldoc) {
		objunref(fb->xmldoc);
	}
	newtFormDestroy(fb->form);
	newtPopWindow();
}

struct form_result *createresult(struct form_box *fbox, const char *node, const char *attr, const char **value) {
	struct form_result *result;

	result = objalloc(sizeof(*result), free_result);

	if (node) {
		if (!attr) {
			ALLOC_CONST(result->keyval, node);
		};
		result->node = xml_getnode(fbox->xsearch, node);
	} else {
		result->node = xml_getfirstnode(fbox->xsearch, NULL);
	}

	if (result->node && attr) {
		*value = xml_getattr(result->node, attr);
	} else if (result->node) {
		*value = result->node->value;
	} else {
		*value = NULL;
	}

	ALLOC_CONST(result->name, attr);
	addtobucket(fbox->results, result);
	return result;
}

extern void addFormEntry(struct form_box *fbox, const char *label, const char *node, const char *attr) {
	struct form_result *result;
	const char *value;

	result = createresult(fbox, node, attr, &value);
	result->type = NEWT_FORM_ENTRYBOX;

	newtFormAddComponent(fbox->form, newtLabel(1, fbox->row, label));
	newtFormAddComponent(fbox->form, 
		newtEntry((fbox->width/2)+1, fbox->row, value, (fbox->width/2)-2, (const char **)&result->value.entry,
					NEWT_ENTRY_SCROLL));
	objunref(result);
	fbox->row++;
}

extern void addFormCheck(struct form_box *fbox, const char *label, const char *node, const char *attr) {
	struct form_result *result;
	const char *value;
	char defval;

	result = createresult(fbox, node, attr, &value);

	if (value) {
		defval = (!strcmp(value, "true")) ? '*' : ' ';
	} else {
		defval = ' ';
	}
	result->type = NEWT_FORM_CHECKBOX;
	newtFormAddComponent(fbox->form, newtLabel(1, fbox->row, label));
	newtFormAddComponent(fbox->form, 
		newtCheckbox((fbox->width/2)+1, fbox->row, NULL, defval, "* ", (char *)&result->value.check)); 
	objunref(result);
	fbox->row++;
}

extern struct form_box *create_form(struct xml_doc *xmldoc, const char *xpath, const char *attrkey,
					int width, int height, const char *title, int flags) {
	struct form_box *fbox;

	fbox = objalloc(sizeof(*fbox), free_form);
	fbox->form = newtForm(NULL, NULL, NEWT_FLAG_NOF12);
	fbox->width = (width <= 30) ? 30 : width;
	fbox->height = height + 5;
	fbox->row = 0;
	ALLOC_CONST(fbox->title, title);
	ALLOC_CONST(fbox->xpath, xpath);
	ALLOC_CONST(fbox->attrkey, attrkey);
	fbox->results = create_bucketlist(0, results_hash);
	fbox->flags = flags;
	fbox->xsearch = xml_xpath(xmldoc, xpath, attrkey);
	if (objref(xmldoc)) {
		fbox->xmldoc = xmldoc;
	}
	return fbox;
}

void delete_node(struct form_box *fbox) {
	const char *akey;
	struct form_result *root, *tnode;
	struct bucket_list *results;

	akey = fbox->attrkey;
	results = fbox->results;

	if (akey) {
		root = bucket_list_find_key(results, akey);
		tnode = bucket_list_find_key(results, NULL);
		if (tnode && root && tnode->node) {
			xml_delete(tnode->node);
		}
		objunref(root);
		objunref(tnode);
	}
}

void save_changes(struct form_box *fbox, const char *xroot, const char *newnodename) {
	const char *akey;
	struct bucket_loop *bloop;
	struct form_result *result;
	struct form_result *root = NULL;
	struct form_result *tnode = NULL;
	struct bucket_list *results;

	akey = fbox->attrkey;
	results = fbox->results;

	if (akey) {
		root = bucket_list_find_key(results, akey);
		tnode = bucket_list_find_key(results, NULL);
		if (tnode && root &&  !tnode->node && strlen(tnode->value.entry) && strlen(root->value.entry)) {
			tnode->node = xml_addnode(fbox->xmldoc, xroot, newnodename, tnode->value.entry, akey, root->value.entry);
		} else if (tnode && tnode->node && strlen(tnode->value.entry)) {
			xml_modify(fbox->xmldoc, tnode->node, tnode->value.entry);
		}
	} else {
		tnode = bucket_list_find_key(results, NULL);
		if (tnode &&  !tnode->node && strlen(tnode->value.entry)) {
			tnode->node = xml_addnode(fbox->xmldoc, xroot, newnodename, tnode->value.entry, NULL, NULL);
		} else if (tnode && tnode->node && strlen(tnode->value.entry)) {
			xml_modify(fbox->xmldoc, tnode->node, tnode->value.entry);
		}
	}

	bloop = init_bucket_loop(results);
	while(bloop && (result = next_bucket_loop(bloop))) {
		if (!result->type == NEWT_FORM_ENTRYBOX) {
			char cb = result->value.check;
			result->value.entry = malloc(6);
			if (cb == '*') {
				strcpy(result->value.entry,"true");
			} else {
				strcpy(result->value.entry,"false");
			}
		}
		if ((tnode && root) || strlen(result->value.entry)) {
			if ((!tnode || !root) && result->node && !result->name) {
				xml_modify(fbox->xmldoc, result->node, result->value.entry);
			} else if (result->node && result->name) {
				xml_setattr(fbox->xmldoc, result->node, result->name, result->value.entry);
			} else if (!result->node && !result->name && akey && result->keyval && strlen(result->value.entry)) {
				struct xml_node *newnode = xml_addnode(fbox->xmldoc, xroot, newnodename, result->value.entry, akey,
									result->keyval);
				objunref(newnode);
			} else if (!result->node && tnode && tnode->node) {
				xml_setattr(fbox->xmldoc, tnode->node, result->name, result->value.entry);
			}
		} else if ((!tnode || !root) && !result->name && result->node && !strlen(result->value.entry)) {
			xml_delete(result->node);
		}
		objunref(result);
	}
	stop_bucket_loop(bloop);

	objunref(root);
	objunref(tnode);
}

extern int dtsrunForm(struct form_box *fbox, const char *xroot, const char *newnode) {
	newtComponent f_yes, f_no, f_del = NULL;
	struct newtExitStruct es;
	int result = 0;

	newtCenteredWindow(fbox->width, fbox->height, fbox->title);

	if ((fbox->flags & DTSFORM_HASDEL) && fbox->xsearch) {
		f_yes = newtButton((fbox->width - 30)/2, fbox->height - 4, "Save");
		f_del = newtButton((fbox->width - 30)/2+10, fbox->height - 4, "Del ");
		f_no = newtButton((fbox->width - 30)/2+20, fbox->height - 4, "Quit");
		newtFormAddComponents(fbox->form, f_yes, f_del, f_no, NULL);
	} else {
		f_yes = newtButton((fbox->width - 20)/2, fbox->height - 4, "Save");
		f_no = newtButton((fbox->width - 20)/2+10, fbox->height - 4, "Quit");
		newtFormAddComponents(fbox->form, f_yes, f_no, NULL);
	}
	newtFormAddHotKey(fbox->form, NEWT_KEY_ESCAPE);
	newtFormRun(fbox->form, &es);

	if (es.u.co == f_yes) {
		save_changes(fbox, xroot, newnode);
		result = 1;
	} else if (f_del && es.u.co == f_del) {
		if (confirmBox("Delete Item ?")) {
			delete_node(fbox);
		}
		result = -1;
	} else {
		result = 0;
	}
	objunref(fbox);

	return result;
}

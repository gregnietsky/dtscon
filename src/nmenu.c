#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dtscon.h"

struct menu {
	newtComponent	list;
	newtComponent	form;
	void		*exit;
	void		*quit;
	void		*back;
	menu_callback	menucmd;
	void		*cbdata;
	int		current;
};

struct menu_list {
	struct bucket_list	*items;
	uint8_t			idnum;
};

int menuRun(struct menu *menu, struct menu_list *menulist) {
	void *result = NULL;
	struct newtExitStruct es;
	struct menu_item *mi;
	
/*
	int pipefd[2];
	if (!pipe(pipefd, O_NONBLOCK)) {
		newtFormWatchFd(menu->form, pipe[0], NEWT_FD_READ);
	}*/

	menu->current = 0;
	newtFormRun(menu->form, &es);
/*	close(pipefd[0]);
	close(pipefd[1]);*/

	if (((es.reason == NEWT_EXIT_HOTKEY) && (es.u.key == NEWT_KEY_ESCAPE)) || (es.reason == NEWT_EXIT_FDREADY)) {
		newtFormDestroy(menu->form);
		newtPopHelpLine();
		newtPopWindow();
		return 0;
	}

	if ((es.reason != NEWT_EXIT_COMPONENT) || !(es.u.co == menu->list)) {
		return 1;
	}

	if (!(result = newtListboxGetCurrent(menu->list))) {
		return 1;
	}

	if ((result == &menu->exit) | (result == &menu->quit)) {
		if (confirmBox(NULL)) {
			newtFormDestroy(menu->form);
			newtPopHelpLine();
			newtPopWindow();
			if (result == &menu->exit) {
				exitnewt();
			}
			return 0;
		} else {
			return 1;
		}
	} else if (result == &menu->back) {
		newtFormDestroy(menu->form);
		newtPopHelpLine();
		newtPopWindow();
		return 0;
	} else {
		if (!(mi = bucket_list_find_key(menulist->items, result))) {
			return 1;
		}
		menu->current = mi->key;
 		if (!mi->callback) {
			textBox(30, "No Callback", mi->name, 2);
		} else {
			mi->callback(mi);
		}
		objunref(mi);
	}
	return 1;
}

static void free_menu(void *data) {
	struct menu *m = data;
	if (m->cbdata) {
		objunref(m->cbdata);
	}
}

extern void initmenu(struct menu_list *menulist, struct menu_item *called, int level, const char* title) {
	struct menu *menu;
	struct bucket_loop *bloop;
	struct menu_item *mi;
	int height = (level) ? 1 : 2;

	menu = objalloc(sizeof(*menu), free_menu);
	if (called) {
		menu->menucmd=called->callback;
		objref(called);
	}
	menu->cbdata=called;
	if (menulist) {
		height = height + bucket_list_cnt(menulist->items);
		menu->list = newtListbox(0, 0, height, NEWT_FLAG_RETURNEXIT | NEWT_FLAG_MOUSEEXIT);

		bloop=init_bucket_loop(menulist->items);
		while(bloop && (mi = next_bucket_loop(bloop))) {
			newtListboxAppendEntry(menu->list, mi->name, &mi->key);
			objunref(mi);
		}
		stop_bucket_loop(bloop);
		if (called) {
			newtListboxSetCurrent(menu->list, called->current);
		}
	} else {
		menu->list = newtListbox(0, 0, height, NEWT_FLAG_RETURNEXIT | NEWT_FLAG_MOUSEEXIT);
	}
	newtListboxSetWidth(menu->list, 22);

	newtOpenWindow(1+level*25, 2, 22, height, title);
	menu->form = newtForm(NULL, NULL, NEWT_FLAG_NOF12);

	if (level) {
		newtPushHelpLine("Select Option Or Press Back/<ESC>");
		newtListboxAppendEntry(menu->list, "Back <ESC>", &menu->back);
		newtFormAddHotKey(menu->form, NEWT_KEY_ESCAPE);
	} else {
		newtPushHelpLine("Select Option Or Exit/Quit");
		newtListboxAppendEntry(menu->list, "Save/Exit", &menu->exit);
		newtListboxAppendEntry(menu->list, "Quit", &menu->quit);
	}

	newtFormAddComponent(menu->form, menu->list);

	if (!called) {
		while(menuRun(menu, menulist));
		objunref(menulist);
		objunref(menu);
	} else if (menuRun(menu, menulist)) {
		objunref(menulist);
		newtFormDestroy(menu->form);
		newtPopHelpLine();
		newtPopWindow();
		mi = menu->cbdata;
		mi->current = menu->current;
		objref(menu->cbdata);
		objunref(menu);
		menu->menucmd(menu->cbdata);
		objunref(mi);
	} else {
		objunref(menulist);
		objunref(menu);
	}
}

int menu_hash(const void *data, int key) {
	int ret;
	const struct menu_item *mi = data;
	const int* hashkey = (key) ? data : &mi->key;

	ret = *hashkey;

	return(ret);
}

static void free_menulist(void *data) {
	struct menu_list *ml = data;
	objunref(ml->items);
}

extern struct menu_list *initMenuList() {
	struct menu_list *menulist;
	if (!(menulist = objalloc(sizeof(*menulist), free_menulist))) {
		return NULL;
	}

	if (!(menulist->items = create_bucketlist(0, menu_hash))) {
		objunref(menulist);
		return NULL;
	}
	menulist->idnum = 0;
	return menulist;
}

static void free_menuitem(void *data) {
	struct menu_item *mi = data;
	if (mi->data) {
		objunref(mi->data);
	}
}

extern void addMenuList(struct menu_list *menulist, const char *name, menu_callback cb, void *data) {
	struct menu_item *item;

	if (!(item = objalloc(sizeof(*item),free_menuitem))) {
		return;
	}

	objlock(menulist);
	ALLOC_CONST(item->name, name);
	item->key = menulist->idnum;
	item->callback = cb;
	if (objref(data)) {
		item->data = data;
	}
	if (addtobucket(menulist->items, item)) {
		menulist->idnum++;
	}
	objunlock(menulist);
	objunref(item);
}

extern void xpath_to_menu(struct menu_list *menulist, struct xml_doc *xmldata, const char *xpath, const char *attrkey, 
				menu_callback cb) {
	struct xml_search *xsearch;
	void *iter;
	struct xml_node *xn;
	const char *name;

	xsearch = xml_xpath(xmldata, xpath, attrkey);
	for(xn = xml_getfirstnode(xsearch, &iter);xn;xn = xml_getnextnode(iter)) {
		if ((name = xml_getattr(xn, attrkey))) {
			addMenuList(menulist, name, cb, xn);
		}
		objunref(xn);
	}
	objunref(iter);
	objunref(xsearch);
}

#include <termios.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include <dtsapp.h>

#include "dtscon.h"

struct winsize ws;
char default_help[] = "<Tab>/<Shift-Tab>/<Arrows> between elements   |  <Enter> selects";
char default_confirm[] = "Are You Sure ? (Yes/No)";

struct newt_exit {
	exit_callback exit;
	void	*data;
};

struct newt_exit exitfunc;

void set_bottom(const char* bot_text) {
	newtDrawRootText(ws.ws_col-strlen(bot_text), -2, bot_text);
	newtRefresh();
}

extern void xmlBox(struct xml_doc *xmldoc, int width, const char *title, int timeout) {
	char *xmlbuf;
	void *buffer;
	buffer = xml_doctobuffer(xmldoc);
	xmlbuf = xml_getbuffer(buffer);
	textBox(width, title, xmlbuf, timeout);
	objunref(buffer);
}

extern void msgBox(int width, const char *title, int timeout, char *buffer, const char *fmt, ...) {
	va_list args;
	size_t size;

	if (!objref(buffer)) {
		return;
	}

	size = objsize(buffer);

    	va_start(args,fmt);
	vsnprintf(buffer, size, fmt, args);
	va_end(args);
	objunref(buffer);
}

extern void textBox(int width, const char *title, const char *message, int timeout) {
	char *text = NULL;
	newtComponent form, tb, button;
	int aw, ah, sw, wm;
	int flags = 0;
	struct newtExitStruct es;

	wm = 6;
	sw = ((width > ws.ws_col-wm) || (width <= 0)) ? ws.ws_col- wm : width - wm;

	if (message) {
		text = newtReflowText((char*)message, sw, 0, (ws.ws_col-wm) - sw, &aw, &ah);
	} else {
		ah = 1;
		aw = width-wm;
	}

	if (ah > ws.ws_row-10) {
		flags = NEWT_FLAG_SCROLL;
		ah = ws.ws_row-10;
	}

	newtCenteredWindow(aw+4, ah+6, title);

	tb = newtTextbox(2, 1, aw, ah, flags | NEWT_FLAG_RETURNEXIT);
	if (text) {
		newtTextboxSetText(tb, text);
	}

	button = newtButton((aw+4-7)/2, ah + 2, "Ok");

	form = newtForm(NULL, NULL, NEWT_FLAG_NOF12 | NEWT_FLAG_RETURNEXIT);
	newtFormAddHotKey(form, NEWT_KEY_ESCAPE);
	if (timeout) {
		newtFormSetTimer(form, timeout*1000);
	}
	newtFormAddComponents(form, tb, button, NULL);

	newtFormRun(form, &es);
	newtFormDestroy(form);
	newtPopWindow();
	if (text) {
		free(text);
	}
}

extern int confirmBox(const char *text) {
	newtComponent f_confirm, b_yes, b_no, label;
	int result = 0;
	int width = 21;
	struct newtExitStruct es;

	if (text) {
		width = strlen(text) + 2;
		label = newtLabel(1, 1, text);
	} else {
		width = strlen(default_confirm) + 2;
		label = newtLabel(1, 1, default_confirm);
	}
	width = (width < 20) ? 20 : width;

	newtCenteredWindow(width, 7, "Confirm");
	f_confirm = newtForm(NULL, NULL, NEWT_FLAG_NOF12);
	b_yes = newtButton((width-16)/2, 3, "Yes");
	b_no = newtButton((width-16)/2+9, 3, "No ");
	newtFormAddComponents(f_confirm, label, b_yes, b_no, NULL);
	newtFormSetCurrent(f_confirm, b_no);
	newtFormAddHotKey(f_confirm, NEWT_KEY_ESCAPE);

	newtFormRun(f_confirm, &es);

	if (es.reason == NEWT_EXIT_COMPONENT) {
		result = (es.u.co == b_yes) ? 1 : 0;
	}

	newtFormDestroy(f_confirm);
	newtPopWindow();
	return result;
}

extern void initNewt(struct menu_list *menulist, const char *wintitle, const char *menutitle, const char *bottom, const 
                     char *help, const char *splash, exit_callback exit, void *cbdata) {
	ioctl(0, TIOCGWINSZ, &ws);
	newtInit();
	newtCls();
	newtDrawRootText((ws.ws_col-strlen(wintitle))/2, 0, wintitle);
	if (splash) {
		textBox(20, "Notice", splash, 5);
	}

	if (!help) {
		set_bottom(default_help);
	} else {
		set_bottom(help);
	}

	exitfunc.exit = exit;
	exitfunc.data = cbdata;
		
	initmenu(menulist, NULL, 0, menutitle);

	newtPopHelpLine();
	newtPopWindow();
	newtClearKeyBuffer();
	newtCls();
	newtFinished();
}

extern void exitnewt() {
	if (exitfunc.exit) {
		exitfunc.exit(exitfunc.data);
	}
}

#include <stdint.h>
#include <framework.h>

/*Forward Decl*/
typedef struct menu_item menu_item;
typedef struct menu_list menu_list;

typedef int	(*menu_callback)(struct menu_item*);
typedef void    (*exit_callback)(void*);

/*Newt*/
extern void textBox(int width, const char *title, const char *message, int timeout);
extern void xmlBox(struct xml_doc *xmldoc, int width, const char *title, int timeout);
extern int confirmBox(const char *text);
extern void initmenu(struct menu_list *menulist, struct menu_item *mi, int level, const char* title);
extern void initNewt(struct menu_list *menulist, const char *wintitle, const char *menutitle, const char *bottom, const 
				char *help, const char *splash, exit_callback exit, void *cbdata);
extern void exitnewt();

/* Form */
typedef struct form_box form_box;

enum form_options {
	DTSFORM_HASDEL = (1 << 0)
};

extern struct form_box *create_form(struct xml_doc *xmldoc, const char *xpath, const char *attrkey, int width, int height, const char *title, int flag);
extern int dtsrunForm(struct form_box *fbox, const char *xroot, const char *newnode);
extern void addFormEntry(struct form_box *fbox, const char *label, const char *node, const char *attr);
extern void addFormCheck(struct form_box *fbox, const char *label, const char *node, const char *attr);

enum menu_flags {
	NMENU_ISMENU = (0 << 0),
	NMENU_DIALOG = (1 << 1),
	NMENU_REDRAW = (2 << 2)
};

/*Menu*/
struct menu_item {
	const char	*name;
	int		key;
	menu_callback	callback;
	void		*data;
	int		current;
};

extern struct menu_list *initMenuList();
extern void addMenuList(struct menu_list *menulist, const char *name, menu_callback cb, void *data);
extern void xpath_to_menu(struct menu_list *menulist, struct xml_doc *xmldata, const char *xpath, const char *attrkey, menu_callback cb);

/*Gen Conf*/
void genconf(struct xml_doc *xmldoc, const char *confdir, const char *xsldir, const char *config);
extern void touch(const char *filename, uid_t user, gid_t group);

/*ip4 util*/
extern const char *cidrtosn(int bitlen, const char *buf, int size);
extern const char *getnetaddr(const char *ipaddr, int cidr, const char *buf, int size);
extern const char *getbcaddr(const char *ipaddr, int cidr, const char *buf, int size);
extern const char *getfirstaddr(const char *ipaddr, int cidr, const char *buf, int size);
extern const char *getlastaddr(const char *ipaddr, int cidr, const char *buf, int size);
extern uint32_t cidrcnt(int bitlen);
extern int reservedip(const char *ipaddr);
extern char* ipv6to4prefix(const char *ipaddr);
extern int check_ipv4(const char* ip, int cidr, const char *test);

/*CURL*/
extern void init_curleasy();
extern void close_curleasy();
extern char *url_escape(char *url);
extern char *url_unescape(char *url);
extern void free_curl(void *curlvar);

/* UTIL*/
extern int is_file(const char *path);
extern int is_dir(const char *path);
extern int is_exec(const char *path);
extern int mk_dir(const char *dir, mode_t mode, uid_t user, gid_t group);

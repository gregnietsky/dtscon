#include <stdint.h>

/*Forward Decl*/
typedef struct menu_item menu_item;
typedef struct menu_list menu_list;
typedef struct xml_node xml_node;
typedef struct xml_search xml_search;
typedef struct xml_doc xml_doc;
typedef struct xslt_doc xslt_doc;

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

/*XML*/
struct xml_attr {
	const char	*name;
	const char	*value;
};

struct xml_node {
	const char		*name;
	const char		*value;
	const char		*key;
	struct bucket_list	*attrs;
	void			*nodeptr;
};

extern struct xml_doc *xml_loaddoc(const char* docfile, int validate);
extern struct xml_node *xml_getfirstnode(struct xml_search *xpsearch, void **iter);
extern struct xml_node *xml_getnextnode(void *iter);
extern struct bucket_list *xml_getnodes(struct xml_search *xpsearch);
extern struct xml_search *xml_xpath(struct xml_doc *xmldata, const char *xpath, const char *attrkey);
extern int xml_nodecount(struct xml_search *xsearch);
extern struct xml_node *xml_getnode(struct xml_search *xsearch, const char *key);
extern const char *xml_getattr(struct xml_node *xnode, const char *attr);
extern void xml_modify(struct xml_doc *xmldoc, struct xml_node *xnode, const char *value);
extern void xml_setattr(struct xml_doc *xmldoc, struct xml_node *xnode, const char *name, const char *value);
extern struct xml_node *xml_addnode(struct xml_doc *xmldoc, const char *xpath, const char *name, const char *value, const char* attrkey, const char* keyval);
extern void xml_delete(struct xml_node *xnode);
extern char *xml_getbuffer(void *buffer);
extern void *xml_doctobuffer(struct xml_doc *xmldoc);
extern const char *xml_getrootname(struct xml_doc *xmldoc);
extern struct xml_node *xml_getrootnode(struct xml_doc *xmldoc);
extern void xml_savefile(struct xml_doc *xmldoc, const char *file, int format, int compress);
extern void xml_createpath(struct xml_doc *xmldoc, const char *xpath);
extern void xml_init();
extern void xml_close();

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

/*XSLT*/
extern struct xslt_doc *xslt_open(const char *xsltfile);
extern void xslt_addparam(struct xslt_doc *xsltdoc, const char *param, const char *value);
extern void xslt_apply(struct xml_doc *xmldoc, struct xslt_doc *xsltdoc, const char *filename, int comp);
extern void xslt_init();
extern void xslt_close();

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
extern void touch(const char *filename, uid_t user, gid_t group);
extern char *b64enc(const char *message, int nonl);
extern char *b64enc_buf(const char *message, uint32_t len, int nonl);
extern int is_file(const char *path);
extern int is_dir(const char *path);
extern int is_exec(const char *path);
extern int mk_dir(const char *dir, mode_t mode, uid_t user, gid_t group);

/* LDAP */
enum ldap_starttls {
	LDAP_STARTTLS_NONE,
	LDAP_STARTTLS_ATTEMPT,
	LDAP_STARTTLS_ENFORCE
};

enum ldap_attrtype {
	LDAP_ATTRTYPE_CHAR,
	LDAP_ATTRTYPE_B64,
	LDAP_ATTRTYPE_OCTET
};

struct ldap_rdn {
	const char *name;
	const char *value;
	struct ldap_rdn *next;
	struct ldap_rdn *prev;
};

struct ldap_attrval {
	int	len;
	enum ldap_attrtype type;
        char *buffer;
};

struct ldap_attr {
        const char *name;
	int count;
        struct ldap_attrval **vals;
	struct ldap_attr *next;
	struct ldap_attr *prev;
};

struct ldap_entry {
	const char *dn;
	const char *dnufn;
	int rdncnt;
	struct ldap_rdn **rdn;
	struct ldap_attr *list;
	struct bucket_list *attrs;
	struct ldap_attr *first_attr;
	struct ldap_entry *next;
	struct ldap_entry *prev;
};

struct ldap_results {
	int count;
	struct ldap_entry *first_entry;
	struct bucket_list *entries;
};

typedef struct ldap_conn ldap_conn;
typedef struct ldap_modify ldap_modify;
typedef struct ldap_add ldap_add;

extern struct ldap_conn *ldap_connect(const char *uri, enum ldap_starttls starttls,int timelimit, int limit, int debug, int *err);
extern int ldap_simplebind(struct ldap_conn *ld, const char *dn, const char *passwd);
extern int ldap_saslbind(struct ldap_conn *ld, const char *mech, const char *realm, const char *authcid,
				const char *passwd, const char *authzid);
extern int ldap_simplerebind(struct ldap_conn *ld, const char *initialdn, const char* initialpw, const char *base, const char *filter, 
					const char *uidrdn, const char *uid, const char *passwd);
extern void ldap_close(struct ldap_conn *ld);

extern const char *ldap_errmsg(int res);

extern struct ldap_results *ldap_search_sub(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...);
extern struct ldap_results *ldap_search_one(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...);
extern struct ldap_results *ldap_search_base(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...);

extern void ldap_unref_entry(struct ldap_results *results, struct ldap_entry *entry);
extern void ldap_unref_attr(struct ldap_entry *entry, struct ldap_attr *attr);
extern struct ldap_entry *ldap_getentry(struct ldap_results *results, const char *dn);
extern struct ldap_attr *ldap_getattr(struct ldap_entry *entry, const char *attr);

extern struct ldap_modify *ldap_modifyinit(const char *dn);
extern int ldap_mod_del(struct ldap_modify *lmod, const char *attr, ...);
extern int ldap_mod_add(struct ldap_modify *lmod, const char *attr, ...);
extern int ldap_mod_rep(struct ldap_modify *lmod, const char *attr, ...);
extern int ldap_domodify(struct ldap_conn *ld, struct ldap_modify *lmod);

extern int ldap_mod_remattr(struct ldap_conn *ldap, const char *dn, const char *attr);
extern int ldap_mod_delattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value);
extern int ldap_mod_addattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value);
extern int ldap_mod_repattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value);

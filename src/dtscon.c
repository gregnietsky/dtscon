#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <framework/framework.h>

#include "dtscon.h"

struct xml_doc *xmldata;
struct arg_opts {
	char *xsl;
	char *confdir;
	char *config;
} xopts;

int LDAP_replica(struct menu_item *mi) {
	struct form_box *fbox;

	fbox = create_form(xmldata, "/config/LDAP/Replica", NULL, 60, 3, mi->name, 0);

	addFormEntry(fbox, "LDAP Replica Server", NULL, NULL);
	addFormEntry(fbox, "LDAP Replica SID", NULL, "sid");
	addFormCheck(fbox, "LDAP Replica Use SSL", NULL, "usessl");

	dtsrunForm(fbox, "/config/LDAP", "Replica");
	return 0;
}

int LDAP_settings(struct menu_item *mi) {
	struct form_box *fbox;

	fbox = create_form(xmldata, "/config/LDAP", "option", 60, 3, mi->name, 0);

	addFormEntry(fbox, "LDAP Replication DN", NULL, "ReplicateDN");
	addFormCheck(fbox, "LDAP Anon Read", NULL, "AnonRead");
	addFormCheck(fbox, "LDAP Backup", NULL, "Backup");

	dtsrunForm(fbox, "/config", "LDAP");
	return 0;
}

int LDAP_config(struct menu_item *mi) {
	struct form_box *fbox;

	fbox = create_form(xmldata, "/config/LDAP/Config/Option", "option", 60, 2, mi->name, 0);

	addFormEntry(fbox, "LDAP Server", "Server", NULL);
	addFormEntry(fbox, "LDAP Username", "Login", NULL);

	dtsrunForm(fbox, "/config/LDAP/Config", "Option");
	return 0;
}

int ldap_menucallback(struct menu_item *mi) {
	struct menu_list *menulist;

	menulist = initMenuList();
	addMenuList(menulist, "Config", LDAP_config, NULL);
	addMenuList(menulist, "Setup", LDAP_settings, NULL);
	addMenuList(menulist, "Replica", LDAP_replica, NULL);
	addMenuList(menulist, "Directories", NULL, NULL);

	initmenu(menulist, mi, 1, mi->name);
	return 0;
}

int SQL_settings_menu(struct menu_item *mi) {
	struct form_box *fbox;

	fbox = create_form(xmldata, "/config/SQL/Option", "option", 60, 18, mi->name, 0);

	addFormEntry(fbox, "MySQL Admin Password", "Password", NULL);
	addFormEntry(fbox, "MySQL Horde User", "WebmailPass", NULL);
	addFormEntry(fbox, "MySQL Packet Filter", "IDPass", NULL);
/*Radius*/
/*	addFormEntry(fbox, "SQL Server For Webmail", "RadiusServ", NULL);*/
/*Server*/
	addFormEntry(fbox, "Web Admin Control", "Control", NULL);
	addFormEntry(fbox, "Forum Admin", "Forum", NULL);
	addFormEntry(fbox, "Cubit Accounting Admin Password", "Cubit", NULL);
	addFormEntry(fbox, "Password Used For Asterisk", "Asterisk", NULL);
	addFormEntry(fbox, "Asterisk SQL Server", "AsteriskServ", NULL);
	addFormEntry(fbox, "Password Used For Master Asterisk", "MAsterisk", NULL);
	addFormEntry(fbox, "Asterisk Master SQL Server", "MAsteriskServ", NULL);
	addFormEntry(fbox, "PostGRE Admin Password", "PGAdmin", NULL);
	addFormEntry(fbox, "Password For E4L DB", "PGExchange", NULL);
	addFormCheck(fbox, "SQL Backup", "Backup", NULL);
	addFormEntry(fbox, "Asterisk OP Pannel PW", "OpSecret", NULL);
	addFormCheck(fbox, "Asterisk DB Backup", "VBackup", NULL);
	dtsrunForm(fbox, "/config/SQL", "Option");
	return 0;
}

int x509_settings_menu(struct menu_item *mi) {
	struct form_box *fbox;

	fbox = create_form(xmldata, "/config/X509/Option", "option", 60, 6, mi->name, 0);

	addFormEntry(fbox, "Country", "Country", NULL);
	addFormEntry(fbox, "State", "State", NULL);
	addFormEntry(fbox, "City", "City", NULL);
	addFormEntry(fbox, "Division", "Division", NULL);
	addFormEntry(fbox, "Name", "Name", NULL);
	addFormEntry(fbox, "Email", "Email", NULL);

	dtsrunForm(fbox, "/config/X509", "Option");
	return 0;
}
	
int ip_settings_menu(struct menu_item *mi) {
	struct form_box *fbox;

	fbox = create_form(xmldata, "/config/IP/SysConf/Option", "option", 60, 16, mi->name, 0);

	addFormEntry(fbox, "Internal Interface", "Internal", NULL);
	addFormEntry(fbox, "External Interface", "External", NULL);
	addFormEntry(fbox, "Default Gateway", "Nexthop", NULL);
	addFormEntry(fbox, "NTP Server", "NTPServer", NULL);
	addFormEntry(fbox, "Bridged Interfaces", "Bridge", NULL);
	addFormEntry(fbox, "Primary DNS", "PrimaryDns", NULL);
	addFormEntry(fbox, "Secondary DNS", "SecondaryDns", NULL);
	addFormEntry(fbox, "Primary Wins", "PrimaryWins", NULL);
	addFormEntry(fbox, "Secondary Wins", "SecondaryWins", NULL);
	addFormEntry(fbox, "DHCP Lease Time", "DHCPLease", NULL);
	addFormEntry(fbox, "DHCP Max Lease Time", "DHCPMaxLease", NULL);
	addFormEntry(fbox, "OpenVPN Network", "OVPNNet", NULL);
	addFormEntry(fbox, "L2TP Network", "L2TPNet", NULL);
	addFormEntry(fbox, "IPSec Network", "VPNNet", NULL);
	addFormEntry(fbox, "Egress Limit", "Egress", NULL);
	addFormEntry(fbox, "Ingress Limit", "Ingress", NULL);

	dtsrunForm(fbox, "/config/IP/SysConf", "Option");
	return 0;
}

int iface_callback(struct menu_item *mi) {
	struct form_box *fbox;
	char xpath[256];

	snprintf(xpath, 255, "/config/IP/Interfaces/Interface[@name = '%s']", mi->name);
	fbox = create_form(xmldata, xpath, "name", 40, 10, mi->name, DTSFORM_HASDEL);

	addFormEntry(fbox, "Interface", mi->name, NULL);
	addFormEntry(fbox, "Interface Name", mi->name, "name");
	addFormEntry(fbox, "Mac Addr", mi->name, "macaddr");
	addFormEntry(fbox, "IP Address", mi->name, "ipaddr");
	addFormEntry(fbox, "Subnet", mi->name, "subnet");
	addFormEntry(fbox, "DHCP Start", mi->name, "dhcpstart");
	addFormEntry(fbox, "DHCP End", mi->name, "dhcpend");
	addFormEntry(fbox, "Ingress Limit", mi->name, "bwin");
	addFormEntry(fbox, "Egress Limit", mi->name, "bwout");
	addFormEntry(fbox, "Advertised Gateway", mi->name, "gateway");

	dtsrunForm(fbox, "/config/IP/Interfaces", "Interface");
	return 0;
}

int int_list_callback(struct menu_item *mi) {
	struct menu_list *menulist;

	menulist = initMenuList();
	xpath_to_menu(menulist, xmldata, "/config/IP/Interfaces/Interface", "name", iface_callback);
	addMenuList(menulist, "Add Interface", iface_callback, NULL);
	initmenu(menulist, mi, 2, mi->name);

	return 0;
}

int ip_callback(struct menu_item *mi) {
	struct menu_list *menulist;

	menulist = initMenuList();
	addMenuList(menulist, "Interfaces", int_list_callback, NULL);
	addMenuList(menulist, "Global Settings", ip_settings_menu, NULL);
	addMenuList(menulist, "Routes", NULL, NULL);
	addMenuList(menulist, "GRE Tunnels", NULL, NULL);
	addMenuList(menulist, "Firewall", NULL, NULL);

	initmenu(menulist, mi, 1, mi->name);
	return 0;
}

int main_menu(struct menu_item *mi) {
	struct xml_node *xn = mi->data;

	if (!strcmp(xn->name, "IP")) {
		ip_callback(mi);
	} else if (!strcmp(xn->name, "X509")) {
		x509_settings_menu(mi);
	} else if (!strcmp(xn->name, "SQL")) {
		SQL_settings_menu(mi);
	} else if (!strcmp(xn->name, "LDAP")) {
		ldap_menucallback(mi);
	} else {
		initmenu(NULL, mi, 1, mi->name);
	}
	return 0;
}

int show_config(struct menu_item *mi) {
	xmlBox(xmldata, -1, "XML Config", 0);
	return 0;
}

void saveconfig(void *data) {
	xml_savefile(xmldata, (const char*)data, 1, 9);
}

int do_genconf(struct menu_item *mi) {
	if (confirmBox("Create config files")) {
		genconf(xmldata, xopts.confdir, xopts.xsl, xopts.config);

		if (!(xmldata = xml_loaddoc(xopts.config, 1))) {
			printf("\nDocument load failed check document / DTD\n");
			return(1);
		}
	}
	return 0;
}

void editconf() {
	char message[700] = "This program is free software: you can redistribute it and/or modify "
			"it under the terms of the GNU General Public License as published by "
			"the Free Software Foundation, either version 2 of the License, or "
			"(at your option) any later version.\n\n"
			"This program is distributed in the hope that it will be useful, "
			"but WITHOUT ANY WARRANTY; without even the implied warranty of "
			"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the "
			"GNU General Public License for more details. "
			"\n\nYou should have received a copy of the GNU General Public License "
			"along with this program.If not, see http://www.gnu.org/licenses/";
	struct menu_list *menulist;
	char xpath[256];

	menulist = initMenuList();
	snprintf(xpath,255,"/%s/*",xml_getrootname(xmldata));

	xpath_to_menu(menulist, xmldata, xpath, "descrip", main_menu);
	addMenuList(menulist, "Display XML", show_config, NULL);
	addMenuList(menulist, "Gen. Config Files", do_genconf, NULL);

	initNewt(menulist, "Distrotech Administration Console", "Main Menu", 
			"Select Option To Manage Quit To Abandon / Exit To Save", NULL, message, saveconfig, xopts.config);
}

void ldaptest(const char *filter) {
	struct ldap_conn *ldap;
/*	struct ldap_modify *lmod;*/
	int res;
	struct ldap_results *results;
	struct ldap_entry *lent;

	if (!(ldap = ldap_connect("ldaps://127.0.0.1", LDAP_STARTTLS_ATTEMPT, 3600, 1000, 0, &res))) {
		printf("Connect Error %i -  %s\n",res, ldap_errmsg(res));
		return;
	}

	if ((res = ldap_saslbind(ldap, "PLAIN", NULL, "admin", "gritt_Oth4" , NULL))) {
		printf("Bind Error %i -  %s\n",res, ldap_errmsg(res));
		ldap_close(ldap);
		return;
	}

/*	if ((res = ldap_simplebind(ldap, "uid=admin,ou=users", "gritt_Oth4"))) {
		printf("Bind Error %i -  %s\n",res, ldap_errmsg(res));
		ldap_close(ldap);
		return;
	}*/

/*	if ((res = ldap_simplerebind(ldap, "uid=ldap_limted_ns2,uid=admin,ou=Users", "peits1Ogg}", 
		NULL, "(&(uid=*)(objectClass=posixAccount))", "uid", "admin", "gritt_Oth4"))) {
		printf("Bind Error %i -  %s\n",res, ldap_errmsg(res));
		ldap_close(ldap);
		return;
	}*/

/*	ldap_delattr(ldap, "uid=gregory,ou=Users", "mailLocalAddress");*/
/*	lmod = ldap_modifyinit("uid=gregory,ou=Users");
	ldap_mod_rep(lmod, "mailLocalAddress", "gregory@smartdns.co.za", "gregory@distrotech.co.za", "gregory@smellc.co.za", "gregory@networksentry.co.za", 
                                               "gloria@networksentry.co.za", "gregory@zatelecom.co.za", "gregory@vbox.co.za", "@zatelecom.co.za", "@networksentry.co.za", 
                                               "@vbox.co.za", NULL);
	if ((res = ldap_domodify(ldap, lmod))) {
		printf("Mod Err: %s\n", ldap_errmsg(res));
	}
	objunref(lmod);*/

	if (!(results = ldap_search_sub(ldap, "", filter, 1, &res, NULL))) {
		printf("Search Error %i -  %s\n",res, ldap_errmsg(res));
		ldap_close(ldap);
		return;
	}

	for(lent = results->first_entry; lent; lent = lent->next) {
		struct ldap_attr *la;
		struct ldap_attrval *lav, **lavals;

		printf("#%s\n", lent->dnufn);
		printf("dn: %s\n", lent->dn);

		for (la = lent->first_attr;la;la = la->next) {
			for(lavals = la->vals; *lavals; lavals++) {
				lav = *lavals;
				switch (lav->type) {
					case LDAP_ATTRTYPE_CHAR:
						printf("%s: %s\n", la->name, lav->buffer);
						break;
					case LDAP_ATTRTYPE_B64:
						printf("%s:\n%s", la->name, lav->buffer);
						break;
					case LDAP_ATTRTYPE_OCTET:
						printf("%s: <BINARY DATA>\n", la->name);
						break;
				}
			}
			ldap_unref_attr(lent, la);
		}
		printf("\n");
		ldap_unref_entry(results, lent);
	}
	objunref(results);
	ldap_close(ldap);
}

int main(int argc, char *argv[]) {
	char *xsl = "/var/spool/apache/htdocs/ns/config/xsl";
	char *confdir = "/var/spool/apache/htdocs/ns/config";
	char *defconf = "netsentry.xml";
	char *config = NULL;
	int acnt;

	startthreads();
	xml_init();
	xslt_init();

	for (acnt = 1; acnt < argc; acnt++) {
		if (!strcmp(argv[acnt], "-config")) {
			config = argv[++acnt];
		} else if (!strcmp(argv[acnt], "-dir")) {
			confdir = argv[++acnt];
		} else if (!strcmp(argv[acnt], "-xsl")) {
			xsl = argv[++acnt];
		}
	}

	if (!config) {
		config = objalloc(strlen(confdir)+strlen(defconf)+2, NULL);
		sprintf(config, "%s/%s", confdir, defconf);
	}

	if (!(xmldata = xml_loaddoc(config, 1))) {
		printf("\nDocument load failed check document / DTD\n");
		return(1);
	}

	xopts.config = config;
	xopts.confdir = confdir;
	xopts.xsl = xsl;

	if (!strcmp(argv[0], "genconf") || ((argc > 1) && !strcmp(argv[1], "genconf"))) {
		genconf(xmldata, xopts.confdir, xopts.xsl, xopts.config);
		xmldata = NULL;
	} else if (!strcmp(argv[0], "ldap") || ((argc > 1) && !strcmp(argv[1], "ldap"))) {
		if (argc > 2) {
			ldaptest(argv[2]);
		} else {
			ldaptest(NULL);
		}
	} else {
		editconf();
	}


	if (xmldata) {
		objunref(xmldata);
	}
	xslt_close();
	xml_close();
	objunref(config);
	stopthreads();
	return(0);
}

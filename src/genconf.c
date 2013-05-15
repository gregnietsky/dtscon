/* TODO XXXX

set internal bits if ip is zero to zconf ip
add a default VOIP node 

LCRDTMF="info";
LCRFROMU="false";
LCRPROTO="SIP";
LCRREG="true";
LCRSRTP="false";
LCRVIDEO="true";

 agents.conf backup chan_dahdi.conf dahdi.conf dahdi_dyn.conf dahdir.conf
 exten_blf.conf gnugk.conf lcr.conf lroute.conf misdn.conf mrtg.conf
 musiconhold.conf printcap rc.wanpipe
*/

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
#include <time.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "dtscon.h"
#include <framework.h>

typedef int     (*config_callback)(void*);

struct bucket_list *transforms;

const char *xsldir;
char zcipaddr[16];
char *ldaplimpw;
char *ldapconfpw;
char *ldappw;
char *ldapserv;
const char *serial;

struct xml_doc *xmldoc;
struct xml_search *sconf, *dconf, *mconf, *emconf;

struct domain_config {
	struct xslt_doc *zone;
	struct xslt_doc *key;
	struct xslt_doc *private;
} domxsl;

const char *getdnsserial() {
	struct tm tms;
	time_t ut;
	int ticks;
	const char *ser;

	ser = malloc(11);
	time(&ut);
	localtime_r(&ut, &tms);

	ticks = floor(100*(tms.tm_hour * 3600 + tms.tm_min * 60 + tms.tm_sec) / (86400+1));
	snprintf((char*)ser, 11, "%i%02i%02i%02i\n", tms.tm_year+1900, tms.tm_mon+1,
		tms.tm_mday, ticks);
	return ser;
}

const char *getldaplimpw() {
	FILE *ldaplim;
	char *fname = NULL;
	char ldappw[128];
	struct xml_node *hname;

	if (ldaplimpw && strlen(ldaplimpw)) {
		return ldaplimpw;
	}

	hname = xml_getnode(dconf, "Hostname");
	fname = malloc(strlen(hname->value)+ 14);
	sprintf(fname, "ldap_%s.limited", hname->value);
	objunref(hname);
	if (is_file(fname)) {
		ldaplim = fopen(fname, "r");
		fgets(ldappw, 128, ldaplim);
		fclose(ldaplim);
		ldaplimpw = strdup(ldappw);
		free(fname);
		return ldaplimpw;
	}
	free(fname);
	return NULL;
}

const char *getldapconfpw() {
	FILE *ldapconf;
	char *fname = NULL;
	char ldappw[128];
	struct xml_node *hname;

	if (ldapconfpw && strlen(ldapconfpw)) {
		return ldapconfpw;
	}

	hname = xml_getnode(dconf, "Hostname");
	fname = malloc(strlen(hname->value)+ 13);
	sprintf(fname, "ldap_%s.config", hname->value);
	objunref(hname);
	if (is_file(fname)) {
		ldapconf = fopen(fname, "r");
		fgets(ldappw, 128, ldapconf);
		fclose(ldapconf);
		ldapconfpw = strdup(ldappw);
		free(fname);
		return ldapconfpw;
	}
	free(fname);
	return NULL;
}

const char *getldapadminpw() {
	FILE *ldapsec;
	char ldappwt[128];

	if (ldappw && strlen(ldappw)) {
		return ldappw;
	}

	if (is_file("/etc/ldap.secret")) {
		ldapsec = fopen("/etc/ldap.secret", "r");
		fgets(ldappwt, 128, ldapsec);
		fclose(ldapsec);
		ldappw = strdup(ldappwt);
		return ldappw;
	}
	return NULL;
}

const char *getzconfip() {
	struct xml_node *cn, *in;
	struct xml_search *intiface;
	char xpath[128], ipfile[128];
	FILE *zcip;
	char *maddr;
	int cnt;

	if (strlen(zcipaddr)) {
		return zcipaddr;
	}

	cn = xml_getnode(sconf, "Internal");
	snprintf(xpath, sizeof(xpath)-1, "/config/IP/Interfaces/Interface[ . = '%s' ]", cn->value);

	if (!(intiface = xml_xpath(xmldoc, xpath, "name"))) {
		objunref(cn);
		return NULL;
	}

	if (!(in = xml_getfirstnode(intiface, NULL))) {
		objunref(cn);
		objunref(intiface);
		return NULL;
	}

	maddr = strdup(xml_getattr(in, "macaddr"));
	for(cnt = 0; cnt < strlen(maddr);cnt++) {
		maddr[cnt] = tolower(maddr[cnt]);
	}

	snprintf(ipfile, sizeof(ipfile), "/var/lib/avahi-autoipd/%s", maddr);
	if (is_file(ipfile)) {
		zcip = fopen(ipfile, "r");
		fgets(zcipaddr, sizeof(zcipaddr)-1, zcip);
		fclose(zcip);
	}

	free(maddr);
	objunref(cn);
	objunref(in);
	objunref(intiface);
	return zcipaddr;
}

struct xslt_doc *get_xslt(const char *xslfile) {
	struct xslt_doc *xslt;
	char* file;
	int size;

	size = strlen(xsldir) + strlen(xslfile) + 2;
	
	file = malloc(size);
	snprintf(file, size, "%s/%s", xsldir, xslfile);
	xslt = xslt_open(file);
	free(file);
	return xslt;
}

void ipv6conf() {
	struct xml_node *extif, *extcon, *natip, *extip;
	struct xslt_doc *xslt;
	struct xml_search *xsearch;
	char validip[2];
	char sitip[16];
	char ip6prefix[128];
	char gwout[32];
	char baseprefix[32];
	char xpath[256];
	char *ip624ip = NULL;

	extcon =  xml_getnode(mconf, "Connection");
	extif =  xml_getnode(sconf, "External");

	if (!strcmp(extcon->value, "ADSL") || !strcmp(extif->value, "Dialup")) {
		strncpy(validip, "1", 2);
		strncpy(sitip, "${1}", 16);
		snprintf(ip6prefix, 128, "$(printf \"%%02x%%02x:%%02x%%02x\\n\" $(echo %s | sed \"s/\\./ /g\"))", sitip);
		strncpy(gwout,"${i6prefix}", 32);
		strncpy(baseprefix, "0:0:0", 32);
	} else {
		snprintf(xpath, sizeof(xpath)-1, "/config/IP/Interfaces/Interface[ . = '%s' ]", extif->value);
		xsearch= xml_xpath(xmldoc, xpath, NULL);
		extip = xml_getfirstnode(xsearch, NULL);
		natip =  xml_getnode(sconf, "NattedIP");
		strncpy(sitip, xml_getattr(extip, "ipaddr"), 16);

		if (natip && !reservedip(natip->value)) {
			strncpy(validip, "1", 2);
			if ((ip624ip = ipv6to4prefix(sitip))) {
				strncpy(gwout, ip624ip, 32);
				free(ip624ip);
			}
			ip624ip = ipv6to4prefix(natip->value);
			strncpy(ip6prefix, ip624ip, 128);
			snprintf(baseprefix, 32, "2002:%s", ip624ip);
		} else if (!natip && !reservedip(sitip)) {
			strncpy(validip, "1", 2);
			strncpy(gwout, "${i6prefix}", 32);
			ip624ip = ipv6to4prefix(sitip);
			strncpy(ip6prefix, ip624ip, 128);
			snprintf(baseprefix, 32, "2002:%s", ip624ip);
		} else {
			strncpy(validip, "0", 2);
			strncpy(ip6prefix, "", 128);
			strncpy(gwout, "", 32);
			strncpy(baseprefix, "", 32);
		}

		if (ip624ip) {
			free(ip624ip);
		}
		objunref(natip);
		objunref(extip);
		objunref(xsearch);
	}
	objunref(extcon);
	objunref(extif);

	xslt = get_xslt("radvd.xsl");
	xslt_addparam(xslt, "baseprefix", baseprefix);
	xslt_apply(xmldoc, xslt, "radvd.conf", 0);
	objunref(xslt);

	xslt = get_xslt("ipv6to4a.xsl");
	xslt_addparam(xslt, "baseprefix", baseprefix);
	xslt_apply(xmldoc, xslt, "ipv6to4.addr", 0);
	objunref(xslt);

	xslt = get_xslt("ipv6to4.xsl");
	xslt_addparam(xslt, "baseprefix", baseprefix);
	xslt_addparam(xslt, "ip6prefix", ip6prefix);
	xslt_addparam(xslt, "sitip", sitip);
	xslt_addparam(xslt, "gwout", gwout);
	xslt_apply(xmldoc, xslt, "ipv6to4", 0);
	objunref(xslt);
}

void vpnconf() {
	struct xml_node *vpn;
	struct xslt_doc *xslt;
	char *ip, *tmp;
	int sn;
	char nw[16], nm[16];

	if ((vpn = xml_getnode(sconf, "L2TPNet"))) {
		ip = (char*)vpn->value;
		tmp = rindex(ip, '/');
		tmp[0] = '\0';
		tmp++;
		sn = atoi(tmp);

		xslt = get_xslt("ippool_l2tp.xsl");
		xslt_addparam(xslt, "nwaddr", getnetaddr(ip, sn, nw, 16));
		xslt_addparam(xslt, "netmask", cidrtosn(sn, nm, 16));
		xslt_apply(xmldoc, xslt, "ippool_l2tp", 0);
		objunref(xslt);
		objunref(vpn);
	} else {
		touch("ippool_l2tp", 80, 80);
	}

	if ((vpn = xml_getnode(sconf, "OVPNNet"))) {
		ip = (char*)vpn->value;
		tmp = rindex(ip, '/');
		tmp[0] = '\0';
		tmp++;
		sn = atoi(tmp);

		xslt = get_xslt("openvpn.xsl");
		xslt_addparam(xslt, "netmask", cidrtosn(sn, nm, 16));
		xslt_apply(xmldoc, xslt, "openvpn.conf", 0);
		objunref(xslt);
		objunref(vpn);
	} else {
		touch("openvpn.conf", 80, 80);
	}

	if ((vpn = xml_getnode(sconf, "VPNNet"))) {
		char pool[10];
		ip = (char*)vpn->value;
		tmp = rindex(ip, '/');
		tmp[0] = '\0';
		tmp++;
		sn = atoi(tmp);

		xslt = get_xslt("racoon.xsl");
		xslt_addparam(xslt, "vpnsubnet", cidrtosn(sn, nm, 16));
		xslt_addparam(xslt, "vpnnwaddr", getnetaddr(ip, sn, nw, 16));
		snprintf(pool, 10, "%i", cidrcnt(sn)-3);
		xslt_addparam(xslt, "vpnpool", pool);
		xslt_apply(xmldoc, xslt, "racoon.conf", 0);
		objunref(xslt);
		objunref(vpn);
	} else {
		xslt = get_xslt("racoon.xsl");
		xslt_addparam(xslt, "vpnsubnet", "");
		xslt_addparam(xslt, "vpnnwaddr", "");
		xslt_addparam(xslt, "vpnpool", "");
		xslt_apply(xmldoc, xslt, "racoon.conf", 0);
		objunref(xslt);
	}
}

void ifaceconf() {
	struct xml_search *xsearch;
	struct xml_node *iface;
	struct xslt_doc *ifup, *ifbw, *ppp, *hostapd;
	void *iter;
	char *fname;
	char idnum[2];
	int cnt=1;

	ppp = get_xslt("pppup.xsl");
	xslt_addparam(ppp, "id", "0");
	xslt_apply(xmldoc, ppp, "pppup.ppp0", 0);
	objunref(ppp);

	if ((xsearch = xml_xpath(xmldoc, "/config/IP/ADSL/Links/Link", NULL))) {
		for(iface = xml_getfirstnode(xsearch, &iter); iface; iface = xml_getnextnode(iter)) {
			fname = malloc(11);
			sprintf(idnum, "%i", cnt);
			snprintf(fname, 11, "pppup.ppp%s\n", idnum);
			ppp = get_xslt("pppup.xsl");
			xslt_addparam(ppp, "id", idnum);
			xslt_apply(xmldoc, ppp, fname, 0);
			free(fname);
			objunref(ppp);
			cnt++;

			objunref(iface);
		}
		objunref(iter);
		objunref(xsearch);
	}

	if ((xsearch= xml_xpath(xmldoc, "/config/IP/Interfaces/Interface[not(contains(.,':'))]", NULL))) {
		for(iface = xml_getfirstnode(xsearch, &iter); iface; iface = xml_getnextnode(iter)) {
			fname = malloc(6 + strlen(iface->value));
			ifup = get_xslt("ifup.xsl");
			xslt_addparam(ifup, "iface", iface->value);
			xslt_addparam(ifup, "zconfip", getzconfip());
			snprintf(fname, 6 + strlen(iface->value), "ifup.%s\n", iface->value);
			xslt_apply(xmldoc, ifup, fname, 0);
			objunref(ifup);
			free(fname);

			fname = malloc(6 + strlen(iface->value));
			ifbw = get_xslt("ifbw.xsl");
			xslt_addparam(ifbw, "iface", iface->value);
			snprintf(fname, 6 + strlen(iface->value), "ifbw.%s\n", iface->value);
			xslt_apply(xmldoc, ifbw, fname, 0);
			objunref(ifbw);
			free(fname);

			objunref(iface);
		}
		objunref(iter);
		objunref(xsearch);
	}

	if ((xsearch= xml_xpath(xmldoc, "/config/IP/WiFi[@type != 'Hotspot']", NULL))) {
		for(iface = xml_getfirstnode(xsearch, &iter); iface; iface = xml_getnextnode(iter)) {
			fname = malloc(9 + strlen(iface->value));
			hostapd = get_xslt("hostapd.xsl");
			xslt_addparam(hostapd, "wifi", iface->value);
			snprintf(fname, 9 + strlen(iface->value), "hostapd.%s\n", iface->value);
			xslt_apply(xmldoc, hostapd, fname, 0);
			objunref(hostapd);
			free(fname);

			objunref(iface);
		}
		objunref(iter);
		objunref(xsearch);
	}
}

void chilliconf() {
	struct xml_search *xsearch, *isearch;
	struct xml_node *root, *dom, *hname, *iiface, *hs;
	struct xslt_doc *hsphp, *hsiup, *hscnf;
	const char *serial;
	char xpath[256];
	char ipbuf[15];
	char ipbuf2[15];
	char uamkey[33];
	unsigned char digest[16];
	char md5buf[1024];
	char *fname, *uam, *fqdn;
	void *iter;
	int i;

	dom = xml_getnode(dconf, "Domain");
	hname = xml_getnode(dconf, "Hostname");
	root = xml_getrootnode(xmldoc);
	serial = xml_getattr(root, "serial");

	iiface = xml_getnode(sconf, "Internal");
	snprintf(xpath, sizeof(xpath)-1, "/config/IP/Interfaces/Interface[ . = '%s' ]", iiface->value);
	objunref(iiface);

	i = strlen(hname->value) + strlen(dom->value) + 2;
	fqdn = malloc(i);
	snprintf(fqdn, i, "%s.%s", hname->value, dom->value);

	xsearch= xml_xpath(xmldoc, xpath, NULL);
	iiface = xml_getfirstnode(xsearch, NULL);
	snprintf(md5buf, 1023, "%s%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s%s", fqdn,
		xml_getattr(iiface, "name"), xml_getattr(iiface, "ipaddr"), xml_getattr(iiface, "subnet"), 
		iiface->value, xml_getattr(iiface, "dhcpstart"), xml_getattr(iiface, "dhcpend"),
		xml_getattr(iiface, "bwin"), xml_getattr(iiface, "bwout"), xml_getattr(iiface, "macaddr"), 
		xml_getattr(iiface, "gateway"),
		getnetaddr(xml_getattr(iiface, "ipaddr"), atoi(xml_getattr(iiface, "subnet")), ipbuf, 15),
		getbcaddr(xml_getattr(iiface, "ipaddr"), atoi(xml_getattr(iiface, "subnet")), ipbuf2, 15),
		serial);

	md5sum(digest, md5buf, strlen(md5buf));
	for(i = 0; i < 16; ++i) {
		sprintf(&uamkey[i*2], "%02x", (unsigned int)digest[i]);
	}

	objunref(iiface);
	objunref(xsearch);
	objunref(root);
	objunref(dom);
	objunref(hname);

	hsphp = get_xslt("chilli-php.xsl");
	xslt_addparam(hsphp, "uamsecret", uamkey);
	xslt_apply(xmldoc, hsphp, "chilli.php", 0);
	objunref(hsphp);

	if (!(xsearch= xml_xpath(xmldoc, "/config/IP/WiFi[@type = 'Hotspot']", NULL))) {
		free(fqdn);
		return;
	}

	for(hs = xml_getfirstnode(xsearch, &iter); hs; hs = xml_getnextnode(iter)) {
		fname = malloc(12 + strlen(hs->value));
		hsiup = get_xslt("chilli-up.xsl");
		xslt_addparam(hsiup, "hspot", hs->value);
		snprintf(fname, 11 + strlen(hs->value), "chilli-up.%s\n", hs->value);
		xslt_apply(xmldoc, hsiup, fname, 0);
		objunref(hsiup);
		free(fname);

		fname = malloc(14 + strlen(hs->value));
		hscnf = get_xslt("chilli-conf.xsl");
		xslt_addparam(hscnf, "hspot", hs->value);
		xslt_addparam(hscnf, "uamsecret", uamkey);
		if (is_file("/var/spool/apache/htdocs/hotspot/user.php")) {
			char buf[128];

			snprintf(xpath, sizeof(xpath)-1, "/config/IP/Interfaces/Interface[ . = '%s' ]", hs->value);
			isearch= xml_xpath(xmldoc, xpath, NULL);
			iiface = xml_getfirstnode(isearch, NULL);
			snprintf(buf, 127, "http://%s:3990", xml_getattr(iiface, "ipaddr"));
			uam = url_escape(buf);
			objunref(iiface);
			objunref(isearch);

			snprintf(buf, 127, "uamhomepage http://%s/hotspot/user.php?uam_url=%s", fqdn, uam);
			xslt_addparam(hscnf, "uamhome", buf);
			free_curl(uam);
		} else {
			xslt_addparam(hscnf, "uamhome", "");
		}
		snprintf(fname, 13 + strlen(hs->value), "chilli-conf.%s\n", hs->value);
		xslt_apply(xmldoc, hscnf, fname, 0);
		objunref(hscnf);
		free(fname);
		objunref(hs);
	}
	free(fqdn);
	objunref(iter);
	objunref(xsearch);
}

void dnsconfig() {
	struct xslt_doc *xslt;
	struct xml_node *dn;
	char *dynkey = NULL;
	char *smartkey = NULL;
	char *file;
	int size;

	if ((dn = xml_getnode(dconf, "DynKey"))) {
		dynkey = b64enc(dn->value, 1);
		xslt = get_xslt("dnsupdate.xsl");
		xslt_addparam(xslt, "dynb64key", dynkey);
		xslt_apply(xmldoc, xslt, "dnsupdate", 0);
		objunref(xslt);
		objunref(dn);
	}

	if ((dn = xml_getnode(dconf, "SmartKey"))) {
		smartkey = b64enc(dn->value, 1);
		xslt = get_xslt("dompkey.xsl");
		xslt_addparam(xslt, "key", smartkey);
		xslt_apply(xmldoc, xslt, "zones/dyndns.private", 0);
		objunref(xslt);
		objunref(dn);
	}

	xslt = get_xslt("named.xsl");
	xslt_addparam(xslt, "dynb64key", dynkey);
	xslt_addparam(xslt, "smart64key", (smartkey) ? smartkey : "");
	xslt_apply(xmldoc, xslt, "named.conf", 0);
	objunref(xslt);


	if ((dn = xml_getnode(dconf, "Domain"))) {
		xslt = get_xslt("domzone.xsl");
		size = strlen(dn->value)+7;
		file=malloc(size+1);
		snprintf(file, size, "zones/%s", dn->value);
		xslt_addparam(xslt, "domain", dn->value);
		xslt_addparam(xslt, "addrec", "3");
		xslt_addparam(xslt, "serial", serial);
		xslt_apply(xmldoc, xslt, file, 0);
		free(file);
		objunref(xslt);

		xslt = get_xslt("domzone.xsl");
		xslt_addparam(xslt, "domain", dn->value);
		xslt_addparam(xslt, "addrec", "1");
		xslt_addparam(xslt, "serial", serial);
		xslt_apply(xmldoc, xslt, "zones/domain.ext", 0);
		objunref(xslt);

		xslt = get_xslt("domkey.xsl");
		xslt_addparam(xslt, "domain", dn->value);
		xslt_addparam(xslt, "key", dynkey);
		xslt_apply(xmldoc, xslt, "zones/nsupdate.key", 0);
		objunref(xslt);

		xslt = get_xslt("dompkey.xsl");
		xslt_addparam(xslt, "key", dynkey);
		xslt_apply(xmldoc, xslt, "zones/nsupdate.private", 0);
		objunref(xslt);
		objunref(dn);
	}

	if ((dn = xml_getnode(dconf, "DynZone"))) {
		xslt = get_xslt("domkey.xsl");
		xslt_addparam(xslt, "domain", dn->value);
		xslt_addparam(xslt, "key", smartkey);
		xslt_apply(xmldoc, xslt, "zones/dyndns.key", 0);
		objunref(xslt);
		objunref(dn);
	}

	objunref(dynkey);
	objunref(smartkey);
}

void astrisk() {
	struct xslt_doc *amodxslt, *iaxxslt, *sipxslt;

	amodxslt = get_xslt("astmod.xsl");
	xslt_addparam(amodxslt, "woomera", (is_file("/etc/asterisk/woomera.conf")) ? "1" : "0");
	xslt_addparam(amodxslt, "g729", (is_file("/usr/lib/asterisk/modules-10/codec_g729.so")) ? "1" : "0");
	xslt_addparam(amodxslt, "g723", (is_file("/usr/lib/asterisk/modules-10/codec_g723.so")) ? "1" : "0");
	xslt_addparam(amodxslt, "misdn", (is_file("/dev/mISDN")) ? "1" : "0");
	xslt_apply(xmldoc, amodxslt, "astmod.conf", 0);
	objunref(amodxslt);

	iaxxslt = get_xslt("iax.xsl");
	xslt_addparam(iaxxslt, "useg729", (is_file("/usr/lib/asterisk/modules-10/codec_g729.so")) ? "1" : "0");
	xslt_addparam(iaxxslt, "useg723", (is_file("/usr/lib/asterisk/modules-10/codec_g723.so")) ? "1" : "0");
	xslt_addparam(iaxxslt, "haslocal", (is_file("/etc/asterisk/iax.conf.local")) ? "1" : "0");
	xslt_apply(xmldoc, iaxxslt, "iax.conf", 0);
	objunref(iaxxslt);

	sipxslt = get_xslt("sip.xsl");
	xslt_addparam(sipxslt, "useg729", (is_file("/usr/lib/asterisk/modules-10/codec_g729.so")) ? "1" : "0");
	xslt_addparam(sipxslt, "useg723", (is_file("/usr/lib/asterisk/modules-10/codec_g723.so")) ? "1" : "0");
	xslt_addparam(sipxslt, "usetls", (is_dir("/etc/openssl/voipca")) ? "1" : "0");
	xslt_apply(xmldoc, sipxslt, "sip.conf", 0);
	objunref(sipxslt);
}

void exports() {
	struct xslt_doc *exxslt;
	exxslt = get_xslt("exports.xsl");


	xslt_addparam(exxslt, "ubuntud", (is_file("/tftpboot/Ubuntu/desktop-i386.iso")) ? "/tftpboot/Ubuntu/Desktop" : "");
	xslt_addparam(exxslt, "ubuntus", (is_file("/tftpboot/Ubuntu/server-i386.iso")) ? "/tftpboot/Ubuntu/Server" : "");
	xslt_addparam(exxslt, "install", (is_dir("/mnt/dev")) ? "/mnt/dev" : "");
	xslt_addparam(exxslt, "tinycore", (is_dir("/tftpboot/TinyCore")) ? "/tftpboot/TinyCore" : "");
	xslt_apply(xmldoc, exxslt, "exports", 0);

	objunref(exxslt);
}

void samba() {
	struct xslt_doc *smbxslt;

	smbxslt = get_xslt("smbconf.xsl");
	xslt_addparam(smbxslt, "avahi", (strlen(getzconfip())) ? "1" : "0");
	xslt_addparam(smbxslt, "dhcp", (is_file("/var/run/dhclient.pid")) ? "1" : "0");
	xslt_addparam(smbxslt, "torrent", (is_dir("/root/torrent")) ? "1" : "0");
	xslt_addparam(smbxslt, "cdrom", (is_dir("/dev/cdrom")) ? "1" : "0");
	xslt_addparam(smbxslt, "backup", (is_dir("/var/spool/backup")) ? "1" : "0");
	xslt_addparam(smbxslt, "linadmin", (getgrnam("linux admin users")) ? "1" : "0");
/*	xslt_addparam(smbxslt, "linadmin", "0");*/

	xslt_apply(xmldoc, smbxslt, "smb.conf", 0);
	objunref(smbxslt);
}

void iptables() {
	char *smartkey = NULL;
	struct xslt_doc *ipdown, *iptables, *iptables2;
	struct xml_node *dn;

	if ((dn = xml_getnode(dconf, "SmartKey"))) {
		smartkey = b64enc(dn->value, 1);
		objunref(dn);
	}

	ipdown = get_xslt("ipdown.xsl");
	xslt_addparam(ipdown, "smartkey", (smartkey) ? smartkey : "");
	xslt_apply(xmldoc, ipdown, "ipdown", 0);
	objunref(ipdown);

	iptables = get_xslt("iptables.xsl");
	xslt_addparam(iptables, "zcipaddr", getzconfip());
	xslt_apply(xmldoc, iptables, "iptables", 0);
	objunref(iptables);

	iptables2 = get_xslt("iptables2.xsl");
	xslt_addparam(iptables2, "smartkey", (smartkey) ? smartkey : "");
	xslt_apply(xmldoc, iptables2, "iptables2", 0);
	objunref(iptables);

	objunref(smartkey);
}

void squid() {
	struct xslt_doc *sgxslt, *scxslt;

	sgxslt = get_xslt("sglists.xsl");

	xslt_addparam(sgxslt, "filter", "Allow");
	xslt_addparam(sgxslt, "type", "Domain");
	xslt_apply(xmldoc, sgxslt, "local_allow_domains", 0);
	xslt_clearparam(sgxslt);

	xslt_addparam(sgxslt, "filter", "Deny");
	xslt_addparam(sgxslt, "type", "Domain");
	xslt_apply(xmldoc, sgxslt, "local_denyw_domains", 0);
	xslt_clearparam(sgxslt);

	xslt_addparam(sgxslt, "filter", "Allow");
	xslt_addparam(sgxslt, "type", "URL");
	xslt_apply(xmldoc, sgxslt, "local_allow_urls", 0);
	xslt_clearparam(sgxslt);

	xslt_addparam(sgxslt, "filter", "Deny");
	xslt_addparam(sgxslt, "type", "URL");
	xslt_apply(xmldoc, sgxslt, "local_deny_urls", 0);
	xslt_clearparam(sgxslt);

	xslt_addparam(sgxslt, "filter", "Allow");
	xslt_addparam(sgxslt, "type", "Keyword");
	xslt_apply(xmldoc, sgxslt, "local_allow_exp", 0);
	xslt_clearparam(sgxslt);

	xslt_addparam(sgxslt, "filter", "Deny");
	xslt_addparam(sgxslt, "type", "Keyword");
	xslt_apply(xmldoc, sgxslt, "local_deny_exp", 0);
	xslt_clearparam(sgxslt);
	objunref(sgxslt);

	scxslt = get_xslt("squid.xsl");
	xslt_addparam(scxslt, "unlinkd",(is_exec("/usr/libexec/squid/unlinkd")) ? "/usr/libexec/squid/unlinkd" : "/usr/libexec/unlinkd");
	xslt_apply(xmldoc, scxslt, "squid.conf", 0);
	objunref(scxslt);
}

void mail() {
	struct xslt_doc *msxslt, *smxslt, *soxslt;

	msxslt = get_xslt("mailscanner.xsl");
	xslt_addparam(msxslt, "msgsign",
		(is_file("/opt/MailScanner/etc/reports/en/inline.sig.txt") &&
		 is_file("/opt/MailScanner/etc/reports/en/inline.sig.html")) ? "yes" : "no");
	xslt_apply(xmldoc, msxslt, "mailscanner.conf", 0);
	objunref(msxslt);

	smxslt = get_xslt("sendmail.xsl");
	if (is_file("/etc/ipsec.d/cacerts/server_cacert.pem")) {
		xslt_addparam(smxslt, "cacert", "/etc/ipsec.d/cacerts/server_cacert.pem");
		xslt_addparam(smxslt, "crlcert", "/etc/ipsec.d/crls/server_crl.pem");
	} else {
		xslt_addparam(smxslt, "cacert", "/etc/ipsec.d/cacerts/cacert.pem");
		xslt_addparam(smxslt, "crlcert", "/etc/ipsec.d/crls/crl.pem");
	}
	xslt_apply(xmldoc, smxslt, "sendmail.mc", 0);
	objunref(smxslt);

	soxslt = get_xslt("sogo.xsl");
	xslt_addparam(soxslt, "ldaplimpw", (getldaplimpw()) ? ldaplimpw : "");
	xslt_apply(xmldoc, soxslt, "sogo.conf", 0);
	objunref(soxslt);
}

void dhcpclientfw() {
	struct xslt_doc *dhcpfwxslt;

	dhcpfwxslt = get_xslt("dhclient-fw.xsl");
	xslt_addparam(dhcpfwxslt, "zcipaddr", getzconfip());
	xslt_apply(xmldoc, dhcpfwxslt, "dhclient-fw", 0);
	objunref(dhcpfwxslt);
}


void autofs() {
	struct xslt_doc *afsxslt;

	afsxslt = get_xslt("autofs.xsl");
	xslt_addparam(afsxslt, "cd", (is_file("/dev/cdrom")) ? "1" : "0");
	xslt_apply(xmldoc, afsxslt, "autofs.conf", 0);
	objunref(afsxslt);
}

void sqlpasswd() {
	struct xslt_doc *xslt;
	struct xml_node *dn;
	char *dynkey;

	xslt = get_xslt("sqlpasswd.xsl");
		if ((dn = xml_getnode(dconf, "DynKey"))) {
		dynkey = b64enc(dn->value, 1);
		xslt_addparam(xslt, "tsigkey", dynkey);
		xslt_apply(xmldoc, xslt, "sqlpasswd", 0);
		objunref(xslt); 
		objunref(dynkey); 
		objunref(dn);
	}
}

void tftptmpl_config() {
	char *spaconf[] = {"spa2102","spa3102","spa901","spa921","spa922","spa941","spa942","spa962","spa8000"};
	struct xslt_doc *spaxslt, *ylxslt;
	char conffile[32];
	int cnt;

	spaxslt = get_xslt("lsysspa.xsl");
	for(cnt=0;cnt < sizeof(spaconf)/sizeof(spaconf[0]);cnt++) {
		xslt_addparam(spaxslt, "model", spaconf[cnt]);
		snprintf(conffile, sizeof(conffile), "tftptmpl/%s.cfg", spaconf[cnt]);
		xslt_apply(xmldoc, spaxslt, conffile, 0);
		xslt_clearparam(spaxslt);
	}
	objunref(spaxslt);

	ylxslt = get_xslt("yealink.xsl");
	for(cnt=0;cnt <= 9;cnt++) {
		snprintf(conffile, sizeof(conffile), "tftptmpl/y00000000000%i.cfg", cnt);
		xslt_apply(xmldoc, ylxslt, conffile, 0);
		xslt_clearparam(ylxslt);
	}
	objunref(ylxslt);
}

void domain_config(const char *domain, const char *key, int addrec) {
	const char *b64key;
	char *conffile;
	int cfsize;
	char addrecp[2];

	cfsize = strlen(domain) + 15;
	conffile = malloc(cfsize);

	xslt_addparam(domxsl.zone, "domain", domain);

	snprintf(addrecp, sizeof(addrecp), "%i", addrec);
	xslt_addparam(domxsl.zone, "addrec", addrecp);
	
	xslt_addparam(domxsl.zone, "serial", serial);

	snprintf(conffile, cfsize, "zones/%s", domain);
	xslt_apply(xmldoc, domxsl.zone, conffile, 0);
	xslt_clearparam(domxsl.zone);

	if (key) {
		b64key = b64enc(key, 1);
		xslt_addparam(domxsl.key, "domain", domain);
		xslt_addparam(domxsl.key, "key", b64key);
		snprintf(conffile, cfsize, "zones/%s.key", domain);
		xslt_apply(xmldoc, domxsl.key, conffile, 0);
		xslt_clearparam(domxsl.key);
		

		xslt_addparam(domxsl.private, "domain", domain);
		xslt_addparam(domxsl.private, "key", b64key);
		snprintf(conffile, cfsize, "zones/%s.private", domain);
		xslt_apply(xmldoc, domxsl.private, conffile, 0);
		xslt_clearparam(domxsl.private);
		objunref((void*)b64key);
	}

	free(conffile);
}

void create_zone_configs() {
	struct xml_search *xsearch;
	struct xml_node *xn;
	void *iter;
	const char *domain, *key, *internal;

	if (!(xsearch= xml_xpath(xmldoc, "/config/DNS/Hosted/Domain", "domain"))) {
		return;
	}

	for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
		domain = xml_getattr(xn, "domain");
		key = xml_getattr(xn, "key");
		internal = xml_getattr(xn, "internal");
		if (strlen(key) && !strcmp(internal, "true")) {
			domain_config(domain, key, 1);
		}
		objunref(xn);
	}
	objunref(xsearch);
	objunref(iter);
}

void create_rev_configs() {
	struct xml_search *xsearch;
	struct xml_node *xn;
	void *iter;

	if (!(xsearch= xml_xpath(xmldoc, "/config/DNS/InAddr/Reverse", NULL))) {
		return;
	}

	for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
		domain_config(xn->value, NULL, 0);
		objunref(xn);
	}
	objunref(xsearch);
	objunref(iter);
}

void run_xslt(const char *xslfile, const char *conffile) {
	struct xslt_doc *xslt;

	xslt = get_xslt(xslfile);
	xslt_apply(xmldoc, xslt, conffile, 0);
	objunref(xslt);
}

void create_static_configs() {
	run_xslt("iftab.xsl", "iftab");
	run_xslt("crontab.xsl","crontab");
	run_xslt("voicemail.xsl","voicemail.conf");
	run_xslt("providers.xsl","providers.conf");
	run_xslt("intinfo.xsl","intinfo.inc");
	run_xslt("rctos.xsl","rc.tos");
	run_xslt("ntp.xsl","ntp.conf");
	run_xslt("clamav.xsl","clamav.conf");
	run_xslt("clamstart.xsl","clamd.start");
	run_xslt("gretun.xsl","tunnels");
	run_xslt("hosts.xsl","hosts");
	run_xslt("fetchmailrc.xsl","fetchmailrc");
	run_xslt("logonbat.xsl","logon.bat");
	run_xslt("dhclient.xsl","dhclient.conf");
	run_xslt("mailfilter.xsl","filename.rules.conf");
	run_xslt("radclients.xsl","clients.conf");
	run_xslt("radiusclient.xsl","radiusclient.conf");
	run_xslt("radcserver.xsl","radcserver");
	run_xslt("radproxy.xsl","proxy.conf");
	run_xslt("faxtty.xsl","faxtty");
	run_xslt("faxconfig.xsl","faxconfig");
	run_xslt("hosts.xsl","hosts");
	run_xslt("fetchmailrc.xsl","fetchmailrc");
	run_xslt("secret.xsl","secret");
	run_xslt("diald.xsl","diald.scr");
	run_xslt("odbc.xsl","odbc.ini");
	run_xslt("ooh323.xsl","ooh323.conf");
	run_xslt("ldaprep.xsl","ldap.replica");
	run_xslt("slapd.xsl","slapd.conf");
	run_xslt("procmail.xsl","procmailrc.pub");
	run_xslt("rcmail.xsl","rc.mail");
	run_xslt("pppup3g.xsl","pppup.ppp3g");
	run_xslt("rcppp.xsl","rc.ppp");
	run_xslt("resolv.xsl","resolv.conf");
	run_xslt("hostname.xsl","HOSTNAME");
	run_xslt("idnszone.xsl","idnszones");
	run_xslt("ednszone.xsl","ednszones");
	run_xslt("caconf.xsl","ca.conf");
	run_xslt("voipca.xsl","voipca.conf");
	run_xslt("servssl.xsl","server.conf");
	run_xslt("servsslv.xsl","voipssl.conf");
	run_xslt("rcinterface.xsl","rc.interface");
	run_xslt("ip6tables.xsl","ip6tables");
	run_xslt("filtercnf.xsl","filter.cnf");
	run_xslt("filtercnf.xsl","filter.conf");
	run_xslt("freshclam.xsl","freshclam.conf");
	run_xslt("frox.xsl","frox.conf");
	run_xslt("krb5.xsl","krb5.conf");
	run_xslt("dnsfwd.xsl","forwarders.static");
	run_xslt("dhcpd6.xsl","dhcpd6.conf");
	run_xslt("dhcpd.xsl","dhcpd.conf");
	run_xslt("submit.xsl","submit.mc");
	run_xslt("inittab.xsl","inittab");
	run_xslt("mgetty.xsl","mgetty.conf");
	run_xslt("rcmount.xsl","rc.mount");
	run_xslt("rchfax.xsl","rc.hfax");
	run_xslt("t38modem.xsl","t38modem_start");
	run_xslt("nettalkvol.xsl","AppleVolumes.default");
	run_xslt("avahi-daemon.xsl","avahi-daemon.conf");
	run_xslt("diald-3g.xsl","diald.3g");
	run_xslt("exclude-nfs.xsl","exclude.nfs");
	run_xslt("options.xml","options");
	run_xslt("portidmap.xsl","port-id-map");
	run_xslt("sysvars.xsl","sysvars");
}

void set_ifaceattr(struct xml_node *node, const char *nodeip) {
	struct xml_search *ifsearch;
	struct xml_node *xn;
	void *iter;
	
	if (!(ifsearch = xml_xpath(xmldoc, "/config/IP/Interfaces/Interface[(@ipaddr != '0.0.0.0') and (@subnet != '32')]", NULL))) {
		return;
	}

	for(xn = xml_getfirstnode(ifsearch, &iter); xn; xn = xml_getnextnode(iter)) {
		const char *ip = xml_getattr(xn, "ipaddr");
		int sn = atoi(xml_getattr(xn, "subnet"));

		if (check_ipv4(ip, sn, nodeip)) {
			char *bif, *bif2;
			bif = strdup(xn->value);
			bif2 = rindex(bif, ':');
			if (bif2 && (bif != bif2)) {
				bif2[0] = '\0';
			}
			xml_setattr(xmldoc, node, "iface", bif);
			free(bif);
		}
		objunref(xn);
	}
	objunref(iter);
	objunref(ifsearch);
}

void setovpnroute(const char *ip,int sn) {
	struct xml_search *ifsearch;
	struct xml_node *xn;
	void *iter;
	int cnt;
	int len;
	struct subnet *snet;
	
	struct subnet {
		const char *ip;
		int  sn;
	};

	struct subnet priv[] = {{"192.168.0.0", 16}, {"172.16.0.0", 12}, {"10.0.0.0", 8}, {NULL}};

	if (!(ifsearch = xml_xpath(xmldoc, "/config/IP/Interfaces/Interface[(@ipaddr != '0.0.0.0') and (@subnet != '32')]", NULL))) {
		return;
	}

	len = sizeof(priv)/sizeof(priv[0]);
	snet=(struct subnet*)&priv[len-1];

	snet->ip = ip;
	snet->sn = sn;

	if (!snet->ip) {
		len--;

	}

	for(xn = xml_getfirstnode(ifsearch, &iter); xn; xn = xml_getnextnode(iter)) {
		const char *ip = xml_getattr(xn, "ipaddr");

		xml_setattr(xmldoc, xn, "ovpn", "0");
		for(cnt=0; cnt < len;cnt++) {
			snet=(struct subnet*)&priv[cnt];
			if (check_ipv4(snet->ip, snet->sn, ip)) {
				xml_setattr(xmldoc, xn, "ovpn", "1");
			}
		}
		objunref(xn);
	}
	objunref(iter);
	objunref(ifsearch);
}

void setrevdnsxml(const char *inaddr, const char *match) {
	struct xml_search *xsearch;
	char xpath[512];

	snprintf(xpath, 512, "/config/DNS/InAddr/Reverse[ . = '%s']", inaddr);
	if ((xsearch = xml_xpath(xmldoc, xpath, NULL))) {
		objunref(xsearch);
		return;
	}
	xml_addnode(xmldoc, "/config/DNS/InAddr", "Reverse", inaddr, "fwdmatch", match);
}

void setrevdns(int cidr, const char *ipaddr) {
	uint32_t ip_n;
	uint8_t *ip = (uint8_t*)&ip_n;
	int cnt;
	char inaddr[29];
	char match[16];

	if (!strcmp("0.0.0.0",ipaddr) || (cidr >= 32)) {
		return;
	}

	inet_pton(AF_INET, ipaddr, &ip_n);

	if (cidr > 24) {
		for(cnt=ip[3];cnt <= ip[3]+(1 << (32 - cidr))-1;cnt++) {
			snprintf(inaddr, 29, "%i.%i.%i.%i.in-addr.arpa", cnt, ip[2], ip[1], ip[0]);
			snprintf(match, 16, "%i.%i.%i.%i", ip[0], ip[1], ip[2], cnt);
			setrevdnsxml(inaddr, match);
		}
	} else if (cidr > 16) {
		for(cnt=ip[2];cnt <= ip[2]+(1 << (24 - cidr))-1;cnt++) {
			snprintf(inaddr, 29, "%i.%i.%i.in-addr.arpa", cnt, ip[1], ip[0]);
			snprintf(match, 16, "%i.%i.%i", ip[0], ip[1], cnt);
			setrevdnsxml(inaddr, match);
		}
	} else if (cidr > 8) {
		for(cnt=ip[1];cnt <= ip[1]+(1 << (16 - cidr))-1;cnt++) {
			snprintf(inaddr, 29, "%i.%i.in-addr.arpa", cnt, ip[0]);
			snprintf(match, 16, "%i.%i", ip[0], cnt);
			setrevdnsxml(inaddr, match);
		}
	} else if (cidr > 0) {
		for(cnt=ip[0];cnt <= ip[0]+(1 << (8 - cidr))-1;cnt++) {
			snprintf(inaddr, 29, "%i.in-addr.arpa", cnt);
			snprintf(match, 16, "%i", cnt);
			setrevdnsxml(inaddr, match);
		}
	}
}

const char *ldap_server() {
	struct xml_node *xn;
	struct xml_search *xsearch;
	void *iter;
	char* locserv = NULL;

	if (ldapserv) {
		return ldapserv;
	}

	if ((xsearch = xml_xpath(xmldoc, "/config/LDAP/Config/Option[@option = 'Server']", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			locserv = malloc(strlen(xn->value)+9);
			sprintf(locserv,"ldaps://%s", xn->value);
			objunref(xn);
		}
		objunref(xsearch);
		objunref(iter);
	}

	if (!locserv) {
		locserv = strdup("ldaps://127.0.0.1");
	}

	if (locserv) {
		ldapserv = strdup(locserv);
		free(locserv);
	}
	return ldapserv;
}

void ldap_pubbox() {
	struct xml_search *xsearch;
	struct ldap_conn *ldap;
	struct xml_node *hname, *mbox, *xn;
	int res;
	struct ldap_results *results;
	struct ldap_entry *lent;
	char *lname;
	void *iter;

	if (!(ldap = ldap_connect(ldap_server(), LDAP_STARTTLS_ATTEMPT, 10, 1000, 0, &res))) {
		return;
	}

	hname = xml_getnode(dconf, "Hostname");
	lname = malloc(strlen(hname->value)+ 36);
	sprintf(lname, "uid=ldap_limted_%s,uid=admin,ou=users", hname->value);
	objunref(hname);
	
	if ((res = ldap_simplebind(ldap, lname, getldaplimpw()))) {
		free(lname);
                ldap_close(ldap);
		return;
	}
	free(lname);

	if (!(results = ldap_search_sub(ldap, "ou=email", "(&(description=*)(sendmailMTAAliasValue=pubbox))", 0, &res, "sendmailMTAKey", "description", NULL))) {
                ldap_close(ldap);
                return;
        }

	if ((xsearch = xml_xpath(xmldoc, "/config/LDAP/PublicMail/MailBox", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			xml_delete(xn);
			objunref(xn);
		}
		objunref(xsearch);
		objunref(iter);
	}

	for(lent = results->first_entry; lent; lent = lent->next) {
		struct ldap_attr *attr;
		struct ldap_attrval *av;
		char *group, *name, *alias;

		attr = ldap_getattr(lent, "description");
		av = attr->vals[0];
		name = av->buffer;
		group = index(name, ':');
		group[0]='\0';
		group++;

		attr = ldap_getattr(lent, "sendmailMTAKey");
		av = attr->vals[0];
		alias = av->buffer;

		mbox = xml_addnode(xmldoc, "/config/LDAP/PublicMail", "MailBox", name, "address", alias);
		xml_setattr(xmldoc, mbox, "group", group);
	}
	objunref(results);
	ldap_close(ldap);
}

void setup_domain() {
	struct xml_search *xsearch;
	struct ldap_results *results;
	struct ldap_entry *lent;
	struct ldap_conn *ldap;
	struct xml_node *hname, *dom, *pmailx, *xn;
	void *iter;
	char *lname, *fqdn, *mailx, *domain;
	const char *ldapuser = NULL;
	int res;

	if (!(ldap = ldap_connect(ldap_server(), LDAP_STARTTLS_ATTEMPT, 60, 1000, 0, &res))) {
		return;
	}

	dom = xml_getnode(dconf, "Domain");
	hname = xml_getnode(dconf, "Hostname");

	lname = malloc(strlen(hname->value)+ 36);
	fqdn = malloc(strlen(hname->value)+strlen(dom->value)+2);
	sprintf(lname, "uid=ldap_config_%s,uid=admin,ou=users", hname->value);
	sprintf(fqdn, "%s.%s", hname->value, dom->value);
	domain = strdup(dom->value);

	objunref(hname);
	objunref(dom);

	if ((xsearch = xml_xpath(xmldoc, "/config/LDAP/Config/Option[@option = 'User']", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			ldapuser = strdup(xn->value);
			objunref(xn);
		}
		objunref(xsearch);
		objunref(iter);
	}
	if (!ldapuser) {
		ldapuser = strdup("uid=admin,ou=users");
	}

	if ((res = ldap_simplebind(ldap, ldapuser, getldapadminpw()))) {
		printf("LDAP Bind Error: %s\n", ldap_errmsg(res));
		free(lname);
		free(fqdn);
		free(domain);
		free((void*)ldapuser);
                ldap_close(ldap);
		return;
	}
	pmailx = xml_getnode(emconf, "MailExchange1");
	if (!pmailx || !strcmp(pmailx->value,fqdn)) {
		int havedom = 0;

		mailx = fqdn;
		if ((results = ldap_search_sub(ldap, "ou=email", "(&(objectClass=sendmailMTAClass)(sendmailMTAClassName=LDAPRoute))", 0, &res, "sendmailMTAClassValue", NULL))) {
			struct ldap_attr *attr;
			struct ldap_attrval *av, **vals;

			lent = results->first_entry;
			attr = ldap_getattr(lent, "sendmailMTAClassValue");
			for(vals = attr->vals; (av = *vals); vals++) {
				if (!strcmp(mailx, av->buffer) || !strcmp(domain, av->buffer)) {
					havedom++;
					break;
				}
			}
			if (!havedom) {
				ldap_mod_addattr(ldap, "sendmailMTAClassName=LDAPRoute,ou=Email", "sendmailMTAClassValue", domain);
			}
			objunref(results);
		}
	}
	if ((results = ldap_search_sub(ldap, "ou=email", "(&(objectClass=sendmailMTAClass)(sendmailMTAClassName=R))", 0, &res, "sendmailMTAClassValue", NULL))) {
		int havedom = 0, havefqdn = 0;
		struct ldap_attr *attr;
		struct ldap_attrval *av, **vals;

		lent = results->first_entry;
		attr = ldap_getattr(lent, "sendmailMTAClassValue");

		for(vals = attr->vals; vals && (av = *vals); vals++) {
			if (!strcmp(domain, av->buffer)) {
				havedom++;
			}
			if (!strcmp(fqdn, av->buffer)) {
				havefqdn++;
			}
			if (havedom && havefqdn) {
				break;
			}
		}
		if (!havedom) {
			ldap_mod_addattr(ldap, "sendmailMTAClassName=R,ou=Email", "sendmailMTAClassValue", domain);
		}
		if (!havefqdn) {
			ldap_mod_addattr(ldap, "sendmailMTAClassName=R,ou=Email", "sendmailMTAClassValue", fqdn);
		}
		objunref(results);
	}

	objunref(pmailx);
	free(lname);
	free(fqdn);
	free(domain);
	ldap_close(ldap);
}

void fixup_config(const char *config) {
	struct xml_node *snode, *iface, *wifi, *xn;
	struct xml_search *xsearch, *ifsearch;
	void *iter;
	char ip4[16];
	char nw[16];
	char bc[16];

	xml_createpath(xmldoc, "/config/IPv6/IPv6to4");
	xml_createpath(xmldoc, "/config/DNS/InAddr");
	xml_createpath(xmldoc, "/config/LDAP/PublicMail");

	serial = getdnsserial();
	snode = xml_getnode(dconf, "Serial");
	xml_modify(xmldoc, snode, serial);
	objunref(snode);

	if ((xsearch = xml_xpath(xmldoc, "/config/DNS/InAddr/Reverse", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			xml_delete(xn);
			objunref(xn);
		}
		objunref(xsearch);
		objunref(iter);
	}

	ldap_pubbox();

	ifsearch = xml_xpath(xmldoc, "/config/IP/Interfaces/Interface", NULL);
	if (ifsearch && (xsearch = xml_xpath(xmldoc, "/config/IP/WiFi[@type = 'Hotspot']", NULL))) {
		for(wifi = xml_getfirstnode(xsearch, &iter); wifi; wifi = xml_getnextnode(iter)) {
			if ((iface = xml_getnode(ifsearch, wifi->value))) {
				getfirstaddr(xml_getattr(iface, "ipaddr"), atoi(xml_getattr(iface, "subnet")) , ip4, 16);
				xml_setattr(xmldoc, iface, "ipaddr", ip4);
				objunref(iface);
			}
			objunref(wifi);
		}
		objunref(xsearch);
		objunref(iter);
	}

	if (ifsearch) {
		for(iface = xml_getfirstnode(ifsearch, &iter); iface; iface = xml_getnextnode(iter)) {
			int sn = atoi(xml_getattr(iface, "subnet"));
			const char *ip = xml_getattr(iface, "ipaddr");
			getnetaddr(ip, sn, nw, 16);
			getbcaddr(ip, sn, bc, 16);
			cidrtosn(sn, ip4, 16);
			xml_setattr(xmldoc, iface, "nwaddr", nw);
			xml_setattr(xmldoc, iface, "netmask", ip4);
			xml_setattr(xmldoc, iface, "bcaddr", bc);
			setrevdns(sn, nw);
			objunref(iface);
		}
		objunref(ifsearch);
		objunref(iter);
	}

	if ((xsearch = xml_xpath(xmldoc, "/config/IP/ADSL/Links/Link", NULL))) {
		int lcnt=1;
		char cnt[3];
		for(iface = xml_getfirstnode(xsearch, &iter); iface; iface = xml_getnextnode(iter)) {
			snprintf(cnt, 3, "%i", lcnt); 
			xml_setattr(xmldoc, iface, "id", cnt);
			lcnt++;
			objunref(iface);
		}
		objunref(iter);
		objunref(xsearch);
	}

	if ((xsearch = xml_xpath(xmldoc, "/config/IP/GRE/Tunnels/Tunnel", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			const char *ip = xml_getattr(xn, "local");
			getfirstaddr(ip, 30, ip4, 16);
			if (!strcmp(ip4, ip)) {
				getlastaddr(ip, 30, ip4, 16);
			}
			getnetaddr(ip, 30, nw, 16);
			getbcaddr(ip, 30, bc, 16);
			xml_setattr(xmldoc, xn, "bcaddr", bc);
			xml_setattr(xmldoc, xn, "nwaddr", nw);
			xml_setattr(xmldoc, xn, "remote", ip4);
			objunref(xn);
		}
		objunref(iter);
		objunref(xsearch);
	}

	if ((xsearch = xml_xpath(xmldoc, "/config/IP/ESP/Tunnels/ESPTunnel", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			const char *ip = xml_getattr(xn, "local");
			int sn;
			char *snc;
			char nwaddr[19];

			if ((snc = rindex(ip, '/'))) {
				snc[0]='\0';
				snc++;

				sn = atoi(snc);
				getnetaddr(ip, sn, nw, 16);
				snprintf(nwaddr, 19, "%s/%i", nw, sn);
				xml_setattr(xmldoc, xn, "nwaddr", nwaddr);
			}
			objunref(xn);
		}
		objunref(iter);
		objunref(xsearch);
	}

	if ((xsearch = xml_xpath(xmldoc, "/config/IP/Routes/Route", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			int sn = atoi(xml_getattr(xn, "subnet"));
			const char *ip = xml_getattr(xn, "network");

			set_ifaceattr(xn, xml_getattr(xn, "gateway"));

			getbcaddr(ip, sn, bc, 16);
			cidrtosn(sn, ip4, 16);
			xml_setattr(xmldoc, xn, "netmask", ip4);
			xml_setattr(xmldoc, xn, "bcaddr", bc);
			getnetaddr(ip, sn, nw, 16);
			setrevdns(sn, nw);
			objunref(xn);
		}
		objunref(iter);
		objunref(xsearch);
	}

	if ((xsearch = xml_xpath(xmldoc, "/config/IP/GenRoutes/Route", NULL))) {
		for(xn = xml_getfirstnode(xsearch, &iter); xn; xn = xml_getnextnode(iter)) {
			set_ifaceattr(xn, xml_getattr(xn, "gateway"));
			objunref(xn);
		}
		objunref(iter);
		objunref(xsearch);
	}

	if ((xn = xml_getnode(sconf, "OVPNNet"))) {
		int sn;
		char *ip = strdup(xn->value);
		char *tmp = rindex(ip, '/');

		if (ip && tmp && (tmp != ip)) {
			tmp[0] = '\0';
			tmp++;
			sn = atoi(tmp);
			setovpnroute(ip,sn);
		}

		if (ip) {
			free(ip);
		}
		objunref(xn);
	}

	setup_domain();
	xml_savefile(xmldoc, config, 1, 9);
}

void init_genconf(struct xml_doc *xdoc, const char *confdir, const char *xdir) {
	xmldoc = xdoc;
	xsldir = xdir;

	init_curleasy();

	mk_dir(confdir, 0750, 80, 80);
	if (!chdir(confdir)) {
		mk_dir("zones", 0750, 80, 80);
		mk_dir("tftptmpl", 0750, 80, 80);
	}

	sconf = xml_xpath(xmldoc, "/config/IP/SysConf/Option", "option");
	dconf = xml_xpath(xmldoc, "/config/DNS/Config/Option", "option");
	mconf = xml_xpath(xmldoc, "/config/IP/Dialup/Option", "option");
	emconf = xml_xpath(xmldoc, "/config/Email/Config/Option", "option");
}

void close_genconf() {
        objunref(sconf);  
        objunref(dconf);
        objunref(mconf);
        objunref(emconf);
 
        close_curleasy();
        if (ldaplimpw) {
                free(ldaplimpw);
		ldaplimpw = NULL;
	}
        if (ldapconfpw) {
                free(ldapconfpw);
		ldapconfpw = NULL;
	}
        if (ldappw) {
                free(ldappw);
		ldappw = NULL;
        }
        if (ldapserv) {
                free(ldapserv);
		ldapserv = NULL;
        }
	if (serial) {
		free((void*)serial);
		serial = NULL;
	}
}

void genconf_dns() {
	domxsl.zone = get_xslt("domzone.xsl");
	domxsl.key = get_xslt("domkey.xsl");
	domxsl.private = get_xslt("dompkey.xsl");

	create_zone_configs();
	create_rev_configs();
	domain_config("0.0.127.in-addr.arpa", NULL, 2);
	dnsconfig();

	objunref(domxsl.zone);
	objunref(domxsl.key);
	objunref(domxsl.private);
}

void genconf(struct xml_doc *xdoc, const char *confdir, const char *xdir, const char *config) {

	init_genconf(xdoc, confdir, xdir);
	fixup_config(config);

	create_static_configs();
	genconf_dns();
	tftptmpl_config();
	astrisk();
	autofs();
	dhcpclientfw();
	exports();
	iptables();
	squid();
	mail();
	samba();
	chilliconf();
	ifaceconf();
	vpnconf();
	ipv6conf();
	sqlpasswd();
	close_genconf();

	objunref(xdoc);
}

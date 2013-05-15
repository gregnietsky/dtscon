#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

extern const char *cidrtosn(int bitlen, const char *buf, int size) {
	uint32_t nm;

	if (!buf) {
		return NULL;
	}

	if (bitlen) {
		nm = ~((1 << (32-bitlen))-1);
	} else {
		nm = 0;
	}

	nm = htonl(nm);
	return inet_ntop(AF_INET, &nm, (char *)buf, size);
}

extern const char *getnetaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip;
	
	if (!buf) {
		return NULL;
	}

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		ip = ntohl(ip);
		ip = ip & ~((1 << (32-cidr))-1);
		ip = htonl(ip);		
	} else {
		ip = 0;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern const char *getfirstaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip;
	
	if (!buf) {
		return NULL;
	}

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		ip = ntohl(ip);
		ip = ip & ~((1 << (32-cidr))-1);
		ip++;
		ip = htonl(ip);		
	} else {
		ip = 1;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern const char *getbcaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip, mask;

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		mask = (1 << (32-cidr))-1;
		ip = ntohl(ip);
		ip = (ip & ~mask) | mask;
		ip = htonl(ip);		
	} else {
		ip = 0;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern const char *getlastaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip, mask;

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		mask = (1 << (32-cidr))-1;
		ip = ntohl(ip);
		ip = (ip & ~mask) | mask;
		ip--;
		ip = htonl(ip);		
	} else {
		ip = 0;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern uint32_t cidrcnt(int bitlen) {
	if (bitlen) {
		return pow(2, (32-bitlen));
	} else {
		return 0xFFFFFFFF;
	}
}

extern int reservedip(const char *ipaddr) {
	uint32_t ip;

	inet_pton(AF_INET, ipaddr, &ip);
	ip = ntohl(ip);

	if (!((0xe0000000 ^ ip) >> 28)) { /* 224/4*/
		return 1;
	} else if (!((0x00000000 ^ ip) >> 24)) { /* 0/8 */
		return 1;
	} else if (!((0x0a000000 ^ ip) >> 24)) { /* 10/8 */
		return 1;
	} else if (!((0x7f000000 ^ ip) >> 24)) { /* 127/8 */
		return 1;
	} else if (!((0x64400000 ^ ip) >> 22)) { /* 100.64/10 */
		return 1;
	} else if (!((0xac100000 ^ ip) >> 20)) { /* 172.16/12 */
		return 1;
	} else if (!((0xc6120000 ^ ip) >> 17)) { /* 198.18/15 */
		return 1;
	} else if (!((0xc0a80000 ^ ip) >> 16)) { /* 192.168/16 */
		return 1;
	} else if (!((0xa9fe0000 ^ ip) >> 16)) { /* 169.254/16 */
		return 1;
	} else if (!((0xc0000200 ^ ip) >> 8)) { /* 192.0.2/24 */
		return 1;
	} else if (!((0xc6336400 ^ ip) >> 8)) { /* 198.51.100/24 */
		return 1;
	} else if (!((0xcb007100 ^ ip) >> 8)) { /* 203.0.113/24 */
		return 1;
	}
	return 0;
}

extern char* ipv6to4prefix(const char *ipaddr) {
	uint32_t ip;
	uint8_t *ipa;
	char *pre6;

	if (!inet_pton(AF_INET, ipaddr, &ip)) {
		return NULL;
	}

	pre6 = malloc(10);
	ipa=(uint8_t*)&ip;
	snprintf(pre6, 10, "%02x%02x:%02x%02x", ipa[0], ipa[1], ipa[2], ipa[3]);
	return pre6;
}

extern int check_ipv4(const char* ip, int cidr, const char *test) {
	uint32_t ip1, ip2;

	inet_pton(AF_INET, ip, &ip1);
	inet_pton(AF_INET, test, &ip2);

	ip1 = ntohl(ip1) >> (32-cidr);
	ip2 = ntohl(ip2) >> (32-cidr);

	if (!(ip1 ^ ip2)) {
		return 1;
	} else {
		return 0;
	}
}

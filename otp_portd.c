#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 4096

#define KEYFILE "/etc/otp_port/server.key"
#define CERTFILE  "/etc/otp_port/server.pem"

#define OTPPORT 8443

/* if NKPORT is 0, disable nocking */
#define NKPORT 8442

/* after connect nkport, user must pass otp in 60 seconds */
#define NKTIMEOUT 60
#define MAXCOUNTPERIP 20

#define MAXCOUNTPERMIN 100

#define MAXCLIENT 1024

typedef struct {
	char IP[INET6_ADDRSTRLEN];
	int count;
	time_t nk_valid_time;
} ClientInfo;

ClientInfo clientinfo[MAXCLIENT];
int clients;
time_t connect_valid_time;
int connect_count;

int otpport = OTPPORT;
int nkport = NKPORT;
int ipv6 = 0;
int ipv4 = 0;
int debug = 0;

int set_socket_non_blocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return -1;
	return 0;
}

void dump_nk()
{
	int i;
	time_t tm;
	time(&tm);
	for (i = 0; i < clients; i++) {
		printf("%s %d %d %ld\n", clientinfo[i].IP, tm < clientinfo[i].nk_valid_time, clientinfo[i].count, clientinfo[i].nk_valid_time);

	}
}

/* return 0 if OK */
int check_client(char *remote_ip)
{
	int i;
	time_t tm;
	int per_client_ok = 0;
	time(&tm);

	if (nkport == 0)
		per_client_ok = 1;
	else
		for (i = 0; i < clients; i++) {
			if ((strcmp(clientinfo[i].IP, remote_ip) == 0) && (tm < clientinfo[i].nk_valid_time) && (clientinfo[i].count < MAXCOUNTPERIP)) {
				clientinfo[i].count++;
				per_client_ok = 1;
			}
		}
	if (per_client_ok == 0)
		return 1;
	if (tm < connect_valid_time) {
		if (connect_count < MAXCOUNTPERMIN) {
			connect_count++;
			return 0;
		}
		return 1;
	}
	connect_valid_time = tm + 60;
	connect_count = 0;
	return 0;
}

void process_nk_connection(int nk_fd, char *remote_ip)
{
	int i;
	time_t tm;
	char buf[MAXBUF];
	time(&tm);
	for (i = 0; i < clients; i++) {
		if ((strcmp(clientinfo[i].IP, remote_ip) == 0) && (tm < clientinfo[i].nk_valid_time)) {
			snprintf(buf, MAXBUF - 1, "you have connected just now %s %d\n", remote_ip, clientinfo[i].count);
			write(nk_fd, buf, strlen(buf));
			return;
		}
	}
	for (i = 0; i < clients; i++) {
		if (tm > clientinfo[i].nk_valid_time) {
			strcpy(clientinfo[i].IP, remote_ip);
			clientinfo[i].nk_valid_time = tm + NKTIMEOUT;
			clientinfo[i].count = 0;
			snprintf(buf, MAXBUF - 1, "nice to meet you %s\n", remote_ip);
			write(nk_fd, buf, strlen(buf));
			return;
		}
	}
	if (i == MAXCLIENT - 1) {
		char *str = "too many connections, try later\n";
		write(nk_fd, str, strlen(str));
		return;
	}
	strcpy(clientinfo[i].IP, remote_ip);
	clientinfo[i].nk_valid_time = tm + NKTIMEOUT;
	clientinfo[i].count = 0;
	clients++;
	snprintf(buf, MAXBUF - 1, "nice to meet you %s\n", remote_ip);
	write(nk_fd, buf, strlen(buf));
	return;
}

void check_val_username(char *p)
{
	while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || (*p == '-') || (*p == '_')))
		p++;
	if (*p)
		exit(0);
}

void check_val_pass(char *p)
{
	while (*p && (*p >= '0' && *p <= '9'))
		p++;
	if (*p)
		exit(0);
}

void check_val_ip(char *p)
{
	while (*p && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F') || (*p == '.') || (*p == ':')))
		p++;
	if (*p)
		exit(0);
}

static const char tbl[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

char *http_head =
    "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-cache\r\nServer: otp web server by james@ustc.edu.cn\r\n\r\n";

void process_request(SSL * ssl, char *remote_ip)
{
	char buf[MAXBUF], http_req[MAXBUF], *p;
	int len;
	len = SSL_read(ssl, http_req, MAXBUF - 1);
	if (len <= 0) {
		return;
	}
	http_req[len] = 0;
	if (memcmp(http_req, "GET /", 5) != 0)
		return;
	if (memcmp(http_req + 5, "favicon.ico", 11) == 0) {
		len = snprintf(buf, MAXBUF - 1, "HTTP/1.0 404 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
		SSL_write(ssl, buf, len);
		return;
	}
	if (http_req[5] == ' ') {	//  / request
		len = snprintf(buf, MAXBUF - 1, "%s%s%s%s",
			       http_head,
			       "<html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1, user-scalable=yes\">"
			       "<style>body{ width: 100%; max-width: 200px; margin: 0 auto; }</style></head><form action=/ method=GET>"
			       "<table style=\"border:0px;\" cellSpacing=0 cellPadding=4 width=300>"
			       "<tr><td>Your IP:</td><td>", remote_ip, "</td></tr>"
			       "<tr><td>UserName:</td><td><input name=\"name\" size=20></td></tr>"
			       "<tr><td>OTP Pass:</td><td><input name=\"pass\" size=20></td></tr>"
			       "<tr><td colspan=2><input type=submit value=\"OTP Authenticate\"></td></tr>" "</table></form>");
		SSL_write(ssl, buf, len);
		return;
	}
	if (http_req[5] != '?')
		return;

	char nullvalue[1], *q, *name, *value = nullvalue;
	char UserName[20], OTPPass[20];
	int hasmore = 1;
	int get_name_value = 0;
	nullvalue[0] = UserName[0] = OTPPass[0] = 0;
	q = http_req + 6;
	name = p = q;
	while (hasmore) {
		switch (*q) {
		case ' ':
		case 0:
			*p = 0;
			hasmore = 0;
			get_name_value = 1;
			break;
		case '&':
			*p = 0;
			hasmore = 1;
			get_name_value = 1;
			break;
		case '=':
			*p = 0;
			hasmore = 1;
			p = q;
			value = q + 1;
			break;
		case '%':{
				char v1 = tbl[(unsigned char)*(q + 1)];
				char v2 = tbl[(unsigned char)*(q + 2)];
				if ((v1 >= 0) && (v2 >= 0)) {
					*p = (v1 << 4) | v2;
					q += 2;
					break;
				} else	// mailform url querystring
					return;
			}
		case '+':
			*p = ' ';
			break;
		default:
			*p = *q;
		}
		if (get_name_value) {
			while (*value == ' ')	// strip start blank
				value++;
			while (*value) {	// strip end blank
				if (value[strlen(value) - 1] == ' ')
					value[strlen(value) - 1] = 0;
				else
					break;
			}

			if (strcmp(name, "name") == 0)
				strncpy(UserName, value, 20);
			else if (strcmp(name, "pass") == 0)
				strncpy(OTPPass, value, 20);
			get_name_value = 0;
			value = nullvalue;
			q++;
			p = name = q;
		} else {
			q++;
			p++;
		}
	}
	len = snprintf(buf, MAXBUF - 1, "%s", http_head);
	SSL_write(ssl, buf, len);
	check_val_username(UserName);
	check_val_pass(OTPPass);
	FILE *fp;
	snprintf(buf, MAXBUF - 1, "/etc/otp_port/otp_verify %s %s %s", UserName, OTPPass, remote_ip);
	fp = popen(buf, "r");
	if (fp == NULL) {
		len = snprintf(buf, MAXBUF - 1, "%s", "call otp_verify error");
		SSL_write(ssl, buf, len);
		return;
	}
	while (fgets(buf, MAXBUF - 1, fp)) {
		SSL_write(ssl, buf, strlen(buf));
	}
	pclose(fp);
	return;
}

/* from https://nachtimwald.com/2014/10/01/enable-dh-and-ecdh-in-openssl-server/ */
/* Generated by "openssl dhparam -C 2236" */
static DH *M_net_ssl_get_dh2236(void)
{
	static unsigned char dh2236_p[] = {
		0x09, 0x5B, 0xED, 0x9D, 0x7B, 0xA5, 0xB8, 0xF7, 0xAE, 0x67, 0x01, 0xCD,
		0xE9, 0x48, 0x9A, 0xAD, 0x97, 0xE6, 0x38, 0x6C, 0x66, 0x33, 0x93, 0xBD,
		0x3E, 0x2C, 0x59, 0x1E, 0xB4, 0x34, 0x3C, 0xDB, 0xE3, 0x3E, 0xC2, 0x4F,
		0xFB, 0xC4, 0x5F, 0x91, 0x07, 0x1A, 0xF2, 0xDB, 0xDB, 0xFC, 0xA4, 0x5D,
		0x75, 0xBB, 0x28, 0x72, 0x98, 0xFE, 0x65, 0x75, 0x9B, 0x44, 0xB3, 0xE1,
		0x20, 0xB2, 0x40, 0xA1, 0xE6, 0x20, 0x4E, 0x0F, 0x8B, 0xD2, 0x8A, 0xAB,
		0x1A, 0xB7, 0x23, 0x57, 0xF1, 0x44, 0xBC, 0x82, 0xB9, 0x5A, 0x3E, 0x56,
		0xEE, 0x15, 0x90, 0x2E, 0x23, 0xF3, 0x30, 0x12, 0x42, 0xE9, 0x24, 0x34,
		0x48, 0xF0, 0x37, 0x97, 0x96, 0x5C, 0xBA, 0x63, 0x85, 0x35, 0x66, 0xCB,
		0xF9, 0x85, 0x8E, 0xDD, 0xEA, 0xE2, 0xD0, 0x5B, 0xA3, 0xDB, 0x7E, 0x6F,
		0x44, 0x2F, 0x54, 0xBC, 0x99, 0x8F, 0x85, 0xD2, 0x0A, 0x50, 0xE3, 0x74,
		0x40, 0xEF, 0xDF, 0x2E, 0x85, 0xC8, 0x1B, 0x68, 0xDE, 0x38, 0x12, 0x9A,
		0xE7, 0x63, 0x32, 0x73, 0x1F, 0x7D, 0xB1, 0xCB, 0xCF, 0x9A, 0xDA, 0xCE,
		0xD2, 0x02, 0xC7, 0xC1, 0xE3, 0xE8, 0xFA, 0xFD, 0x2E, 0xAF, 0xE5, 0x7E,
		0xD3, 0x7B, 0xD8, 0xFC, 0x0D, 0x2E, 0x40, 0xC4, 0x4F, 0xB3, 0xD9, 0xFB,
		0xF4, 0x79, 0x3E, 0xA9, 0xF5, 0xEC, 0xC3, 0xE0, 0x88, 0xC6, 0x90, 0xC0,
		0x53, 0x40, 0xBF, 0x7C, 0xA5, 0xEF, 0x29, 0xFE, 0xBD, 0x2E, 0x27, 0xC7,
		0x5A, 0xFB, 0xD6, 0x21, 0x5E, 0xEB, 0x50, 0xF6, 0x98, 0x7E, 0x1E, 0x19,
		0x1D, 0x1D, 0xF3, 0xE5, 0x9E, 0x5A, 0x1C, 0x43, 0x92, 0x0C, 0x55, 0xF0,
		0x5B, 0xAA, 0x96, 0x7A, 0x4C, 0x1E, 0xF0, 0xF6, 0xDC, 0x5C, 0xF2, 0xCE,
		0x95, 0xC1, 0x4B, 0x92, 0x34, 0xBC, 0x99, 0xAB, 0x33, 0xFF, 0x80, 0x78,
		0xA8, 0x47, 0x24, 0xEF, 0xE8, 0x7B, 0x4F, 0x50, 0xCE, 0x42, 0x9D, 0x47,
		0x2D, 0x36, 0x99, 0xC2, 0x1D, 0x9B, 0x36, 0x34, 0xA7, 0xFC, 0xFC, 0x50,
		0xCD, 0x41, 0xC8, 0x8B,
	};
	static unsigned char dh2236_g[] = {
		0x02,
	};
	DH *dh;
	BIGNUM *dhp_bn, *dhg_bn;

	if ((dh = DH_new()) == NULL)
		return NULL;
	dhp_bn = BN_bin2bn(dh2236_p, sizeof(dh2236_p), NULL);
	dhg_bn = BN_bin2bn(dh2236_g, sizeof(dh2236_g), NULL);
	if (dhp_bn == NULL || dhg_bn == NULL
		|| !DH_set0_pqg(dh, dhp_bn, NULL, dhg_bn)) {
		DH_free(dh);
		BN_free(dhp_bn);
		BN_free(dhg_bn);
		return NULL;
	}
	return dh;
}

const char *const PREFERRED_CIPHERS =
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";

int socket_and_listen(int port)
{
	int socket_fd = -1;
	int enable = 1;

	if (!ipv4) {
		if ((socket_fd = socket(AF_INET6, SOCK_STREAM, 0)) >= 0) {
			struct sockaddr_in6 my_addr6;
			setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
			memset(&my_addr6, 0, sizeof(my_addr6));
			my_addr6.sin6_family = AF_INET6;
			my_addr6.sin6_port = htons(port);
			if (bind(socket_fd, (struct sockaddr *)&my_addr6, sizeof(my_addr6)) < 0) {
				perror("bind");
				exit(-1);
			}
		}
	}
	if (!ipv6 && (socket_fd < 0)) {
		if ((socket_fd = socket(AF_INET6, SOCK_STREAM, 0)) >= 0) {
			struct sockaddr_in my_addr;
			setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
			bzero(&my_addr, sizeof(my_addr));
			my_addr.sin_family = PF_INET;
			my_addr.sin_port = htons(nkport);
			my_addr.sin_addr.s_addr = INADDR_ANY;
			if (bind(socket_fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
				perror("bind");
				exit(-1);
			}
		}
	}
	if (socket_fd < 0) {
		printf("could not create socket\n");
		exit(-1);
	}
	if (listen(socket_fd, 10) == -1) {
		perror("listen");
		exit(1);
	}
	set_socket_non_blocking(socket_fd);
	return socket_fd;
}

void usage()
{
	printf("Usage:\n");
	printf("   opt_portd [ -d ] [ -4 ] [ -6 ] [ web_port ] [ knock_port ]\n");
	printf("        -d enable debug\n");
	printf("        -4 force ipv4\n");
	printf("        -6 force ipv6\n");
	printf("        default port is 8443 8442\n");
	exit(0);
}

char *client_addr(struct sockaddr_storage *remote_addr)
{
	static char hbuf[INET6_ADDRSTRLEN];
	hbuf[0] = 0;
	if (remote_addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *r = (struct sockaddr_in6 *)remote_addr;
		inet_ntop(AF_INET6, &r->sin6_addr, hbuf, sizeof(hbuf));
		if (memcmp(hbuf, "::ffff:", 7) == 0)
			strcpy(hbuf, hbuf + 7);
	} else if (remote_addr->ss_family == AF_INET) {
		struct sockaddr_in *r = (struct sockaddr_in *)remote_addr;
		inet_ntop(AF_INET, &r->sin_addr, hbuf, sizeof(hbuf));
	}
	return hbuf;
}

int main(int argc, char **argv)
{
	int nk_listen_port, otp_listen_port, new_fd;
	SSL_CTX *ctx;
	EC_KEY *ecdh;
	DH *dh;
	int c;
	while ((c = getopt(argc, argv, "d46h")) != EOF)
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case '4':
			ipv4 = 1;
			break;
		case '6':
			ipv6 = 1;
			break;
		case 'h':
			usage();
		};

	if (ipv4 && ipv6) {
		printf("you could not force v4 & v6\n");
		exit(0);
	}

	if (argc - optind >= 1)
		otpport = atoi(argv[optind]);
	if (argc - optind >= 2)
		nkport = atoi(argv[optind + 1]);

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX_set_options(ctx, flags);
	if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh == NULL) {
		printf("Failed to get EC curve");
		SSL_CTX_free(ctx);
		exit(1);
	}
	SSL_CTX_set_tmp_ecdh(ctx, ecdh);
	EC_KEY_free(ecdh);	/* Safe because of reference counts */
	/* Use static DH parameters.  This logic comes from:
	 * http://en.wikibooks.org/wiki/OpenSSL/Diffie-Hellman_parameters
	 * And OpenSSL's docs say "Application authors may compile in DH parameters."
	 */
	dh = M_net_ssl_get_dh2236();
	if (dh == NULL) {
		printf("Failed to get DH params");
		SSL_CTX_free(ctx);
		exit(1);
	}
	SSL_CTX_set_tmp_dh(ctx, dh);
	DH_free(dh);		/* Safe because of reference counts */

	printf("otp web port: %d\nknocking port: %d\n", otpport, nkport);

	if (debug == 0) {
		pid_t pid;
		if ((pid = fork()) != 0)
			exit(0);
		close(0);
		close(1);
		close(2);
		setsid();
		(void)signal(SIGCLD, SIG_IGN);
		(void)signal(SIGHUP, SIG_IGN);

	}
	if (nkport)
		/* 开启NK PORT socket 监听 */
		nk_listen_port = socket_and_listen(nkport);

	/* 开启otp socket 监听 */
	otp_listen_port = socket_and_listen(otpport);

	setuid(65534);		// change to nobody

	while (1) {
		fd_set fds;
		int result;
		struct sockaddr_storage their_addr;
		socklen_t sock_len;
		sock_len = sizeof(struct sockaddr_storage);
		FD_ZERO(&fds);
		if (nkport)
			FD_SET(nk_listen_port, &fds);
		FD_SET(otp_listen_port, &fds);
		result = select(otp_listen_port + 1, &fds, NULL, NULL, NULL);
		if (result <= 0)
			continue;
		if (nkport && FD_ISSET(nk_listen_port, &fds)) {	// new connection to nkport
			if ((new_fd = accept(nk_listen_port, (struct sockaddr *)&their_addr, &sock_len)) == -1)
				continue;
			if (debug)
				printf("new connection to nkocking port: %s\n", client_addr(&their_addr));
			process_nk_connection(new_fd, client_addr(&their_addr));
			close(new_fd);
			continue;
		}
		if (!FD_ISSET(otp_listen_port, &fds))	// new connection to otp_port
			continue;
		if ((new_fd = accept(otp_listen_port, (struct sockaddr *)&their_addr, &sock_len)) == -1)
			continue;
		if (debug)
			printf("new connection to web port: %s\n", client_addr(&their_addr));
		if (check_client(client_addr(&their_addr)) != 0) {
			close(new_fd);
			continue;
		}

		int pid;
		pid = fork();
		if (pid != 0) {	// parent or error
			close(new_fd);
			continue;
		}

		close(nk_listen_port);
		close(otp_listen_port);
		SSL *ssl;
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, new_fd);
		if (SSL_set_cipher_list(ssl, PREFERRED_CIPHERS) != 1) {
			perror("SSL_set_cipher_list");
			close(new_fd);
			exit(0);
		}
		if (SSL_accept(ssl) == -1) {
			perror("accept");
			close(new_fd);
			exit(0);
		}
		process_request(ssl, client_addr(&their_addr));
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(new_fd);
		exit(0);
	}
	exit(0);
}

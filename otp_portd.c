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
#define NKPORT 0

/* after connect nkport, user must pass otp in 60 seconds */
#define NKTIMEOUT 60
#define MAXCOUNT 20

#define MAXCLIENT 1024

typedef struct {
	char IP[20];
	int count;
	time_t nk_valid_time;
} ClientInfo;

ClientInfo clientinfo[MAXCLIENT];
int clients;

int otpport = OTPPORT;
int nkport = NKPORT;

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
	if (nkport == 0)
		return 0;
	time(&tm);
	for (i = 0; i < clients; i++) {
		if ((strcmp(clientinfo[i].IP, remote_ip) == 0) && (tm < clientinfo[i].nk_valid_time) && (clientinfo[i].count < MAXCOUNT)) {
			clientinfo[i].count++;
			return 0;
		}
	}
	return 1;
}

void process_nk_connection(int nk_fd, char *remote_ip)
{
	int i, found = 0;
	time_t tm;
	time(&tm);
	for (i = 0; i < clients; i++) {
		if ((strcmp(clientinfo[i].IP, remote_ip) == 0) && (tm < clientinfo[i].nk_valid_time)) {
			found = 1;
			break;
		}
	}
	if (found) {
		char *str = "you have connected just now\n";
		write(nk_fd, str, strlen(str));
		return;
	}
	for (i = 0; i < clients; i++) {
		if (tm > clientinfo[i].nk_valid_time) {
			strcpy(clientinfo[i].IP, remote_ip);
			clientinfo[i].nk_valid_time = tm + NKTIMEOUT;
			clientinfo[i].count = 0;
			char *str = "nice to meet you\n";
			write(nk_fd, str, strlen(str));
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
	char *str = "nice to meet you\n";
	write(nk_fd, str, strlen(str));
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
	while (*p && ((*p >= '0' && *p <= '9') || (*p == '.')))
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

char *http_head = "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nServer: otp web server by james@ustc.edu.cn\r\n\r\n";

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
		len = snprintf(buf, MAXBUF - 1, "%s%s",
			       http_head,
			       "<html><form action=/ method=GET>"
			       "<table style=\"border:0px;\" cellSpacing=0 cellPadding=4 width=300>"
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

int main(int argc, char **argv)
{
	int nk_listen_port, otp_listen_port, new_fd;
	socklen_t sock_len;
	struct sockaddr_in my_addr, their_addr;
	int enable = 1;
	SSL_CTX *ctx;

	if (argc >= 2)
		otpport = atoi(argv[1]);
	if (argc >= 3)
		nkport = atoi(argv[2]);

	printf("otp port: %d\nnk  port: %d\n", otpport, nkport);
	pid_t pid;
	if ((pid = fork()) != 0)
		exit(0);

	close(0);
	close(1);
	close(2);
	setsid();
	(void)signal(SIGCLD, SIG_IGN);
	(void)signal(SIGHUP, SIG_IGN);

	if (nkport != 0) {
		/* 开启NK PORT socket 监听 */
		if ((nk_listen_port = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			exit(1);
		}
		setsockopt(nk_listen_port, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
		bzero(&my_addr, sizeof(my_addr));
		my_addr.sin_family = PF_INET;
		my_addr.sin_port = htons(nkport);
		my_addr.sin_addr.s_addr = INADDR_ANY;

		if (bind(nk_listen_port, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
			perror("bind");
			exit(1);
		}

		if (listen(nk_listen_port, 10) == -1) {
			perror("listen");
			exit(1);
		}
	}

	/* SSL 库初始化 */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* 载入用户的数字证书 */
	if (SSL_CTX_use_certificate_file(ctx, CERTFILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* 载入用户私钥 */
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* 检查用户私钥是否正确 */
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	/* 开启otp socket 监听 */
	if ((otp_listen_port = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}
	setsockopt(otp_listen_port, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(otpport);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(otp_listen_port, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		exit(1);
	}

	if (listen(otp_listen_port, 10) == -1) {
		perror("listen");
		exit(1);
	}

	if (nkport)
		set_socket_non_blocking(nk_listen_port);
	set_socket_non_blocking(otp_listen_port);

	setuid(65534);

	while (1) {
		fd_set fds;
		int result;
		FD_ZERO(&fds);
		if (nkport)
			FD_SET(nk_listen_port, &fds);
		FD_SET(otp_listen_port, &fds);
		result = select(otp_listen_port + 1, &fds, NULL, NULL, NULL);
		if (result <= 0)
			continue;
		if (nkport && FD_ISSET(nk_listen_port, &fds)) {	// new connection to nkport
			sock_len = sizeof(struct sockaddr);
			/* 等待客户端连上来 */
			if ((new_fd = accept(nk_listen_port, (struct sockaddr *)&their_addr, &sock_len)) == -1)
				continue;
			process_nk_connection(new_fd, inet_ntoa(their_addr.sin_addr));
			close(new_fd);
			continue;
		}
		if (!FD_ISSET(otp_listen_port, &fds))	// new connection to otp_port?
			continue;
		sock_len = sizeof(struct sockaddr);
		/* 等待客户端连上来 */
		if ((new_fd = accept(otp_listen_port, (struct sockaddr *)&their_addr, &sock_len)) == -1)
			continue;
		if (check_client(inet_ntoa(their_addr.sin_addr)) != 0) {
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

		/* 基于 ctx 产生一个新的 SSL */
		SSL *ssl;
		ssl = SSL_new(ctx);
		/* 将连接用户的 socket 加入到 SSL */
		SSL_set_fd(ssl, new_fd);
		/* 建立 SSL 连接 */
		if (SSL_accept(ssl) == -1) {
			perror("accept");
			close(new_fd);
			exit(0);
		}

		process_request(ssl, inet_ntoa(their_addr.sin_addr));
		/* 关闭 SSL 连接 */
		SSL_shutdown(ssl);
		/* 释放 SSL */
		SSL_free(ssl);
		/* 关闭 socket */
		close(new_fd);

		exit(0);
	}
	exit(0);
}

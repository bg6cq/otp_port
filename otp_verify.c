/*

lot of code from https://github.com/fmount/c_otp

*/

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
#include <math.h>

// #define DEBUG 1

#define MAXBUF 4096
#define KEYLEN 16

#define OPTKEYFILE "/etc/otp_port/otp_key.txt"
#define OPENPORTCMD "/etc/otp_port/openport.sh"

/* 
密钥文件 /etc/otp_port/otp_key.txt，只要root可读即可，格式为
16字节base32编码的密钥（原密钥10字节，base32编码后16字节）  空格  用户名
WUGQECLUOFLAEAAZ ussername
*/

void Log(char *s)
{
	FILE *fplog;
	time_t t;
	struct tm *ctm;
	time(&t);
	ctm = localtime(&t);
	fplog = fopen("/var/log/otp_portd.log", "a");
	if (fplog) {
		fprintf(fplog, "%04d.%02d.%02d %02d:%02d:%02d %s\n", ctm->tm_year + 1900, ctm->tm_mon + 1, ctm->tm_mday, ctm->tm_hour, ctm->tm_min, ctm->tm_sec,
			s);
		fclose(fplog);
	}
}

static const int8_t base32_vals[256] = {
	//    This map cheats and interprets:
	//       - the numeral zero as the letter "O" as in oscar
	//       - the numeral one as the letter "L" as in lima
	//       - the numeral eight as the letter "B" as in bravo
	// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0x00
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0x10
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0x20
	14, 11, 26, 27, 28, 29, 30, 31, 1, -1, -1, -1, -1, 0, -1, -1,	// 0x30
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,	// 0x40
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,	// 0x50
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,	// 0x60
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1,	// 0x70
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0x80
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0x90
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0xA0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0xB0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0xC0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0xD0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0xE0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	// 0xF0
};

size_t decode_b32key(uint8_t ** k, size_t len)
{

	size_t keylen;
	size_t pos;
	// decodes base32 secret key
	keylen = 0;
	for (pos = 0; pos <= (len - 8); pos += 8) {
		// MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
		// MB is middle bits             (0x7E == 01111110 ~= MB)
		// LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

		// byte 0
		(*k)[keylen + 0] = (base32_vals[(*k)[pos + 0]] << 3) & 0xF8;	// 5 MSB
		(*k)[keylen + 0] |= (base32_vals[(*k)[pos + 1]] >> 2) & 0x07;	// 3 LSB
		if ((*k)[pos + 2] == '=') {
			keylen += 1;
			break;
		}
		// byte 1
		(*k)[keylen + 1] = (base32_vals[(*k)[pos + 1]] << 6) & 0xC0;	// 2 MSB
		(*k)[keylen + 1] |= (base32_vals[(*k)[pos + 2]] << 1) & 0x3E;	// 5  MB
		(*k)[keylen + 1] |= (base32_vals[(*k)[pos + 3]] >> 4) & 0x01;	// 1 LSB
		if ((*k)[pos + 4] == '=') {
			keylen += 2;
			break;
		}
		// byte 2
		(*k)[keylen + 2] = (base32_vals[(*k)[pos + 3]] << 4) & 0xF0;	// 4 MSB
		(*k)[keylen + 2] |= (base32_vals[(*k)[pos + 4]] >> 1) & 0x0F;	// 4 LSB
		if ((*k)[pos + 5] == '=') {
			keylen += 3;
			break;
		}
		// byte 3
		(*k)[keylen + 3] = (base32_vals[(*k)[pos + 4]] << 7) & 0x80;	// 1 MSB
		(*k)[keylen + 3] |= (base32_vals[(*k)[pos + 5]] << 2) & 0x7C;	// 5  MB
		(*k)[keylen + 3] |= (base32_vals[(*k)[pos + 6]] >> 3) & 0x03;	// 2 LSB
		if ((*k)[pos + 7] == '=') {
			keylen += 4;
			break;
		}
		// byte 4
		(*k)[keylen + 4] = (base32_vals[(*k)[pos + 6]] << 5) & 0xE0;	// 3 MSB
		(*k)[keylen + 4] |= (base32_vals[(*k)[pos + 7]] >> 0) & 0x1F;	// 5 LSB
		keylen += 5;
	}
	(*k)[keylen] = 0;

	return keylen;
}

uint8_t *hmac(unsigned char *key, int kl, uint64_t interval)
{
	return (uint8_t *) HMAC(EVP_sha1(), key, kl, (const unsigned char *)&interval, sizeof(interval), NULL, 0);
}

uint32_t DT(uint8_t * digest)
{
	uint64_t offset;
	uint32_t bin_code;
	offset = digest[19] & 0x0f;
	bin_code = (digest[offset] & 0x7f) << 24 | (digest[offset + 1] & 0xff) << 16 | (digest[offset + 2] & 0xff) << 8 | (digest[offset + 3] & 0xff);
	return bin_code;

}

uint32_t mod_hotp(uint32_t bin_code, int digits)
{
	int power = pow(10, digits);
	uint32_t otp = bin_code % power;
	return otp;
}

uint32_t HOTP(uint8_t * key, size_t kl, uint64_t interval, int digits)
{
	uint8_t *digest;
	uint32_t result;
	uint32_t endianness;

	endianness = 0xdeadbeef;
	if ((*(const uint8_t *)&endianness) == 0xef) {
		interval = ((interval & 0x00000000ffffffff) << 32) | ((interval & 0xffffffff00000000) >> 32);
		interval = ((interval & 0x0000ffff0000ffff) << 16) | ((interval & 0xffff0000ffff0000) >> 16);
		interval = ((interval & 0x00ff00ff00ff00ff) << 8) | ((interval & 0xff00ff00ff00ff00) >> 8);
	};
	digest = (uint8_t *) hmac(key, kl, interval);
	uint32_t dbc = DT(digest);
	result = mod_hotp(dbc, digits);
	return result;

}

#define T0 0
#define DIGITS 6
#define VALIDITY 30
#define TIME 2

int otp_verify(char *key, char *pass)
{
	int keylen;
	uint32_t result;
	time_t t = floor((time(NULL) - T0) / VALIDITY);
	if (strlen(key) != KEYLEN)
		return 1;
	keylen = decode_b32key((uint8_t **) & key, strlen(key));
	result = HOTP((uint8_t *) key, keylen, t, DIGITS);
	if (atoi(pass) == result)
		return 0;
	return 1;
}

char *find_user_key(char *username)
{
	FILE *fp;
	static char key[KEYLEN + 1];
	char buf[MAXBUF];
	key[0] = 0;
	fp = fopen(OPTKEYFILE, "r");
	if (fp == NULL)
		return key;
	while (fgets(buf, MAXBUF - 1, fp)) {
		if (strlen(buf) < KEYLEN + 2)
			continue;
		if (buf[KEYLEN] != ' ')
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		buf[KEYLEN] = 0;
		if (strcmp(buf + KEYLEN + 1, username) == 0) {
			fclose(fp);
			strcpy(key, buf);
			return key;
		}
	}
	fclose(fp);
	return key;
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

int main(int argc, char **argv)
{
	char buf[MAXBUF], *key;
	char *username, *pass, *ip;
	if (argc != 4)
		exit(0);
	username = argv[1];
	pass = argv[2];
	ip = argv[3];

	check_val_username(username);
	check_val_pass(pass);
	check_val_ip(ip);

	setuid(0);		// change to root

	key = find_user_key(username);
	if (key[0] == 0) {
		printf("ERROR\n");
		exit(0);
	}
	if (otp_verify(key, pass) != 0) {	// verify error
		printf("ERROR\n");
		exit(0);
	}
	snprintf(buf, MAXBUF - 1, "%s %s", username, ip);
	Log(buf);
	printf("OK\n");
	snprintf(buf, MAXBUF - 1, "%s %s 2>/dev/null >/dev/null", OPENPORTCMD, ip);
	system(buf);
	exit(0);
}

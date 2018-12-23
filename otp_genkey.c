// QRCode in console
// Author:Jinhill 2016-9-6 cb@ecd.io
// Make: gcc -o qrcode qrcode.c -ldl
// depend on libqrencode.so
//
// Origin Copyright 2010 Google Inc.
// Origin Author: Markus Gutschke
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <assert.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

static enum { QR_UNSET = 0, QR_NONE, QR_ANSI, QR_UTF8 } qr_mode = QR_UNSET;

static const char *urlEncode(const char *s)
{
	const size_t size = 3 * strlen(s) + 1;
	if (size > 10000) {
		// Anything "too big" is too suspect to let through.
		fprintf(stderr, "Error: Generated URL would be unreasonably big.");
		exit(1);
	}
	char *ret = malloc(size);
	char *d = ret;
	do {
		switch (*s) {
		case '%':
		case '&':
		case '?':
		case '=':
 encode:
			snprintf(d, size - (d - ret), "%%%02X", (unsigned char)*s);
			d += 3;
			break;
		default:
			if ((*s && *s <= ' ') || *s >= '\x7F') {
				goto encode;
			}
			*d++ = *s;
			break;
		}
	} while (*s++);
	char *newret = realloc(ret, strlen(ret) + 1);
	if (newret) {
		ret = newret;
	}
	return ret;
}

#define ANSI_RESET        "\x1B[0m"
#define ANSI_BLACKONGREY  "\x1B[30;47;27m"
#define ANSI_WHITE        "\x1B[27m"
#define ANSI_BLACK        "\x1B[7m"
#define UTF8_BOTH         "\xE2\x96\x88"
#define UTF8_TOPHALF      "\xE2\x96\x80"
#define UTF8_BOTTOMHALF   "\xE2\x96\x84"

static void displayQRCode(const char *url)
{
	if (qr_mode == QR_NONE) {
		return;
	}
	int i = 0;
	int x = 0;
	int y = 0;
	// Only newer systems have support for libqrencode. So, instead of requiring
	// it at build-time, we look for it at run-time. If it cannot be found, the
	// user can still type the code in manually, or he can copy the URL into
	// his browser.
	if (!isatty(1)) {
		printf("not running in tty\n");
		return;
	}
	void *qrencode = dlopen("libqrencode.so.2", RTLD_NOW | RTLD_LOCAL);
	if (!qrencode) {
		qrencode = dlopen("libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
	}
	if (!qrencode) {
		qrencode = dlopen("libqrencode.dylib.3", RTLD_NOW | RTLD_LOCAL);
	}
	if (!qrencode) {
		printf("could not find libqrencode.so\n");
		return;
	}
	typedef struct {
		int version;
		int width;
		unsigned char *data;
	} QRcode;
	QRcode *(*QRcode_encodeString8bit) (const char *, int, int) = (QRcode * (*)(const char *, int, int))
	    dlsym(qrencode, "QRcode_encodeString8bit");
	void (*QRcode_free) (QRcode * qrcode) = (void (*)(QRcode *))dlsym(qrencode, "QRcode_free");
	if (QRcode_encodeString8bit && QRcode_free) {
		QRcode *qrcode = QRcode_encodeString8bit(url, 0, 1);
		char *ptr = (char *)qrcode->data;
		// Output QRCode using ANSI colors. Instead of black on white, we
		// output black on grey, as that works independently of whether the
		// user runs his terminals in a black on white or white on black color
		// scheme.
		// But this requires that we print a border around the entire QR Code.
		// Otherwise, readers won't be able to recognize it.
		if (qr_mode != QR_UTF8) {
			for (i = 0; i < 2; ++i) {
				printf(ANSI_BLACKONGREY);
				for (x = 0; x < qrcode->width + 4; ++x)
					printf("  ");
				puts(ANSI_RESET);
			}
			for (y = 0; y < qrcode->width; ++y) {
				printf(ANSI_BLACKONGREY "    ");
				int isBlack = 0;
				for (x = 0; x < qrcode->width; ++x) {
					if (*ptr++ & 1) {
						if (!isBlack) {
							printf(ANSI_BLACK);
						}
						isBlack = 1;
					} else {
						if (isBlack) {
							printf(ANSI_WHITE);
						}
						isBlack = 0;
					}
					printf("  ");
				}
				if (isBlack) {
					printf(ANSI_WHITE);
				}
				puts("    " ANSI_RESET);
			}
			for (i = 0; i < 2; ++i) {
				printf(ANSI_BLACKONGREY);
				for (x = 0; x < qrcode->width + 4; ++x)
					printf("  ");
				puts(ANSI_RESET);
			}
		} else {
			// Drawing the QRCode with Unicode block elements is desirable as
			// it makes the code much smaller, which is often easier to scan.
			// Unfortunately, many terminal emulators do not display these
			// Unicode characters properly.
			printf(ANSI_BLACKONGREY);
			for (i = 0; i < qrcode->width + 4; ++i) {
				printf(" ");
			}
			puts(ANSI_RESET);
			for (y = 0; y < qrcode->width; y += 2) {
				printf(ANSI_BLACKONGREY "  ");
				for (x = 0; x < qrcode->width; ++x) {
					int top = qrcode->data[y * qrcode->width + x] & 1;
					int bottom = 0;
					if (y + 1 < qrcode->width) {
						bottom = qrcode->data[(y + 1) * qrcode->width + x] & 1;
					}
					if (top) {
						if (bottom) {
							printf(UTF8_BOTH);
						} else {
							printf(UTF8_TOPHALF);
						}
					} else {
						if (bottom) {
							printf(UTF8_BOTTOMHALF);
						} else {
							printf(" ");
						}
					}
				}
				puts("  " ANSI_RESET);
			}
			printf(ANSI_BLACKONGREY);
			for (i = 0; i < qrcode->width + 4; ++i) {
				printf(" ");
			}
			puts(ANSI_RESET);
		}
		QRcode_free(qrcode);
	}
	dlclose(qrencode);
}

int base32_encode(const char *data, int length, char *result, int bufSize)
{
	if (length < 0 || length > (1 << 28)) {
		return -1;
	}
	int count = 0;
	if (length > 0) {
		int buffer = data[0];
		int next = 1;
		int bitsLeft = 8;
		while (count < bufSize && (bitsLeft > 0 || next < length)) {
			if (bitsLeft < 5) {
				if (next < length) {
					buffer <<= 8;
					buffer |= data[next++] & 0xFF;
					bitsLeft += 8;
				} else {
					int pad = 5 - bitsLeft;
					buffer <<= pad;
					bitsLeft += pad;
				}
			}
			int index = 0x1F & (buffer >> (bitsLeft - 5));
			bitsLeft -= 5;
			result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
		}
	}
	if (count < bufSize) {
		result[count] = '\000';
	}
	return count;
}

int main(int argc, char *argv[])
{
	char buf[1024];
	char key10bytes[11];
	char keyafterbase32[21];
	if (argc < 3) {
		printf("Usage:\n  otp_genkey username hostname\n");
		return -1;
	}
	if (!RAND_bytes((unsigned char *)key10bytes, 10)) {
		printf("Can't get random number\n");
		exit(0);
	}
	if (base32_encode(key10bytes, 10, keyafterbase32, 20) != 16) {
		printf("base32 len error\n");
		exit(0);
	}
	snprintf(buf, 1024, "otpauth://totp/%s@%s?secret=%s", argv[1], argv[2], keyafterbase32);
	displayQRCode(buf);
	const char *url = urlEncode(buf);
	if (url) {
		printf("\nhttps://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=%s\n\n", url);
		free((void *)url);
	}
	printf("please add following to /etc/otp_port/otp_key.txt\n");
	printf("%s %s\n\n", keyafterbase32, argv[1]);

	return 0;
}

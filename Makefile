all: otp_portd otp_verify otp_genkey

otp_genkey: otp_genkey.c
	gcc -Wall -g -o otp_genkey otp_genkey.c -lssl 

otp_verify: otp_verify.c
	gcc -Wall -g -o otp_verify otp_verify.c -lssl -lm
	chmod u+s otp_verify

otp_portd: otp_portd.c
	gcc -Wall -g -o otp_portd otp_portd.c -lssl

install:
	if [ ! -d /etc/otp_port ]; then mkdir /etc/otp_port; fi
	cp -f otp_verify /etc/otp_port/otp_verify
	chown root /etc/otp_port/otp_verify
	chmod +s /etc/otp_port/otp_verify
	if [ ! -f /etc/otp_port/openport.sh ]; then cp openport.sh /etc/otp_port; fi
	if [ ! -f /etc/otp_port/otp_key.txt ]; then touch /etc/otp_port/otp_key.txt; chmod og-rw /etc/otp_port/otp_key.txt; fi


indent:
	indent otp_portd.c otp_verify.c otp_genkey.c -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
-cli0 -d0 -di1 -nfc1 -i8 -ip0 -l160 -lp -npcs -nprs -npsl -sai \
-saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1

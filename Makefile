all: otp_portd otp_verify

otp_verify: otp_verify.c
	gcc -Wall -g -o otp_verify otp_verify.c -lssl -lm
	chmod u+s otp_verify

otp_portd: otp_portd.c
	gcc -Wall -g -o otp_portd otp_portd.c -lssl

indent:
	indent otp_portd.c otp_verify.c -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
-cli0 -d0 -di1 -nfc1 -i8 -ip0 -l160 -lp -npcs -nprs -npsl -sai \
-saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1

all: logger acmonitor test_aclog rsa_assign_1

rsa_assign_1: rsa_assign_1.c
	gcc rsa_assign_1.c -o rsa_assign_1 -lm -lgmp
	./rsa_assign_1 -g

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c rsa_assign_1.c -lcrypto -ldl -lm -lgmp

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor -lm -lgmp

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf rsa_assign_1
	rm -rf file_*
	rm -rf public.key private.key
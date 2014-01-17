CFLAGS+=-pedantic -ansi -O3 -march=native -fstack-protector -fomit-frame-pointer
PREFIX=

all:
	@echo '[CC] libmiu.so'
	@${CC} ${CFLAGS} -shared -liniparser -ldl -o libmiu.so main.c

install:
	@echo '[INS] libmiu.so'
	@install -m644 libmiu.so ${PREFIX}/lib/libmiu.so
	@echo '[INS] miu.ini'
	@install -m644 example.ini ${PREFIX}/etc/miu.ini

clean:
	@rm *.so

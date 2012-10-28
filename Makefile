CC=clang
CFLAGS=-Wall -Wextra

all:
	@echo '[CC] libmiu.so'
	@${CC} ${CFLAGS} -shared -fPIC -liniparser -ldl -o libmiu.so main.c

clean:
	@rm *.so

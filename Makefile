all:
	${CC} ${CFLAGS} -shared -fPIC -lconfig -ldl -o libmiu.so main.c

clean:
	rm *.o
	rm *.so

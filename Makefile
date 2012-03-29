all:
	${CC} -shared -fPIC -o libmiu.so main.c

clean:
	rm *.o
	rm *.so

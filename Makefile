default:
        gcc -g -O3 -c bloom/bloom.c -o bloom.o
        gcc -g -O3 -c sha256/sha256.c -o sha256.o
        gcc -g -O3 -c base58/base58.c -o base58.o
        gcc -g -O3 -c rmd160/rmd160.c -o rmd160.o
        gcc -g -O3 -c xxhash/xxhash.c -o xxhash.o
        gcc -g -O3 -c hashtable.c -o hashtable.o
        #gcc -g -O3 -c gmpecc.c -o gmpecc.o
        gcc -g -O3 -c util.c -o util.o
        gcc -g -O3 -o keymath keymath.c gmpecc.c util.o  base58.o sha256.o rmd160.o hashtable.o -lgmp
        #rm *.o
clean:
        rm -r *.o

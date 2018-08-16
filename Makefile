##Adapted from http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
CC=gcc
CFLAGS=-Wall -Wextra -std=gnu99 -I. -O3
OBJ = certcheck.o
EXE = certcheck
PATH =   -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib



##Create .o files from .c files. Searches for .c files with same .o names given in OBJ
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(PATH)

##Create executable linked file from object files. 
$(EXE): $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(THREAD) $(PATH)

##Delete object files
clean:
	/bin/rm $(OBJ)

##Performs clean (i.e. delete object files) and deletes executable
clobber: clean
	/bin/rm $(EXE) 

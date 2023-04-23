.SUFFIXES : .c .o

OBJECTS= crypt.o exerMain.o
SRCS= crypt.c exerMain.c
HEADINC= /opt/nfast/c/ctd/gcc/include/pkcs11/
LIBINC= /opt/nfast/c/ctd/gcc/lib/

CC= gcc
CFLAGS= -c

TARGET= cktest

$(TARGET) : $(OBJECTS)
	$(CC) -L$(LIBINC) -o $(TARGET) $(OBJECTS) -lcknfast -lcrypto

.c.o :
	$(CC) -I$(HEADINC) $(CFLAGS) $<

clean :
	rm -rf $(OBJECTS) core $(TARGET)

crypt.o : keyTemplate.h crypt.h crypt.c
exerMain.o : crypt.h ssl.h exerMain.c


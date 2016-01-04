PLATFORM=$(shell uname)
CC = gcc
AR = ar

STATIC_LIB =  lkcp.a
SHARED_LIB = lkcp.so
OBJS = lkcp.o ikcp.o

LLIBS = 
CFLAGS = -c -O3 -Wall -fPIC
LDFLAGS = -O3 -Wall --shared

ifeq ($(PLATFORM),Linux)
else
	ifeq ($(PLATFORM), Darwin)
		LLIBS += -llua
	endif
endif

all : $(SHARED_LIB) $(STATIC_LIB)

$(SHARED_LIB): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LLIBS)

$(STATIC_LIB): $(OBJS)
	$(AR) crs $@ $^

$(OBJS) : %.o : %.c
	$(CC) -o $@ $(CFLAGS) $<

clean : 
	rm -f $(OBJS) $(SHARED_LIB) $(STATIC_LIB)

.PHONY : clean


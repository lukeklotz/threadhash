CC = gcc
DEBUG = -g
WARNINGS = -Wextra
.SUFFIXES:
DEFINES = 
CFLAGS =  $(DEBUG) -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
	 -Wmissing-declarations -Wold-style-definition \
	 -Wmissing-prototypes -Wdeclaration-after-statement \
	 -Wno-return-local-addr -Wunsafe-loop-optimizations \
	 -Wuninitialized -Werror \

THREAD_HASH = thread_hash 

PROGS = $(ARVIK)

all: $(PROGS)

$(THREAD_HASH): $(THREAD_HASH).o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(THREAD_HASH).o: $(THREAD_HASH).c
	$(CC) $(CFLAGS) -c $<

clean cls:
	rm -f $(PROGS) *.o *~ \#*

tar:
	tar cvfa lab3_${LOGNAME}.tar.gz *.[ch] [mM]akefile

git:
	@echo "Enter commit message: "; \
	read msg; \
	git add *.[ch] [mM]akefile && \
	git commit -m "$$msg" && \
	git push 

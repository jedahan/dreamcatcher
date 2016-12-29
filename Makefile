CFLAGS=-Wall -O2 -std=c++0x
LDFLAGS=-ltins -L/usr/local/lib -I/usr/local/include
EXECUTABLES=probecatcher

.PHONY: clean all install

all: $(EXECUTABLES)

probecatcher:
	g++ probecatcher.cpp -o probecatcher $(CFLAGS) $(LDFLAGS)

clean:
	rm $(OBJECTS) $(EXECUTABLES)

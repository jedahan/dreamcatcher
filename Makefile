CFLAGS=-Wall -O2 -std=c++0x
LDFLAGS=-ltins
EXECUTABLES=probecatcher

.PHONY: clean all install

all: $(EXECUTABLES)

probecatcher:
	g++ probecatcher.cpp -o probecatcher $(CFLAGS) $(LDFLAGS)

clean:
	rm $(OBJECTS) $(EXECUTABLES)


CXX = g++-9
LD = /usr/lib/gcc/x86_64-linux-gnu/9/collect2

CXXFLAGS = -std=c++1z -Iinclude -O0 -g
LDFLAGS_START = -plugin /usr/lib/gcc/x86_64-linux-gnu/9/liblto_plugin.so \
			-plugin-opt=/usr/lib/gcc/x86_64-linux-gnu/9/lto-wrapper \
			-plugin-opt=-fresolution=/tmp/ccPAi1AJ.res \
			-plugin-opt=-pass-through=-lgcc_s \
			-plugin-opt=-pass-through=-lgcc \
			-plugin-opt=-pass-through=-lc \
			-plugin-opt=-pass-through=-lgcc_s \
			-plugin-opt=-pass-through=-lgcc \
			--build-id \
			--eh-frame-hdr \
			-m elf_x86_64 \
			--hash-style=gnu \
			--as-needed \
			-dynamic-linker /lib64/ld-linux-x86-64.so.2 \
			-z relro 

LDFLAGS_START += /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crt1.o \
			/usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crti.o \
			/usr/lib/gcc/x86_64-linux-gnu/9/crtbegin.o 

LDFLAGS_START += -L/usr/lib/gcc/x86_64-linux-gnu/9 \
-L/usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu \
			-L/usr/lib/gcc/x86_64-linux-gnu/9/../../../../lib \
			-L/lib/x86_64-linux-gnu \
			-L/lib/../lib -L/usr/lib/x86_64-linux-gnu \
			-L/usr/lib/../lib \
			-L/usr/lib/gcc/x86_64-linux-gnu/9/../../..

LDFLAGS = -lLIEF -lpthread -lstdc++ -lm -lgcc_s -lgcc -lc -lgcc_s -lgcc -T reserve.ld

LDFLAGS_END = /usr/lib/gcc/x86_64-linux-gnu/9/crtend.o \
			/usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crtn.o

BIN = loader

OBJEXT = .o
SRCS = src/IO.cpp src/UIO.cpp src/Proxy.cpp src/SyscallDecoder.cpp
OBJS = $(SRCS:.cpp=$(OBJEXT))

# Build targets

all: $(BIN)
.PHONY: clean

src/raw_syscall.o: src/raw_syscall.S
	$(CXX) $(CXXFLAGS) -c -o $@ $< 

$(OBJS): %$(OBJEXT): %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $< 

$(BIN): $(OBJS) src/main.cpp src/raw_syscall.o
	$(CXX) $(CXXFLAGS) -c -o src/main.o src/main.cpp 
#$(CXX) -v -o $@ $(OBJS) src/main.o $(LDFLAGS)
	$(LD) $(LDFLAGS_START) -o $@ $(OBJS) src/raw_syscall.o src/main.o $(LDFLAGS) $(LDFLAGS_END)

clean:
	rm -f $(BIN)
	rm -f src/*.o

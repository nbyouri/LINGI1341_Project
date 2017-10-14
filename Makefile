CC      = cc
CFLAGS += -Wall # Enable the 'all' set of warnings
#CFLAGS += -Werror # Treat all warnings as error
CFLAGS += -Wshadow # Warn when shadowing variables
CFLAGS += -Wextra # Enable additional warnings
CFLAGS += -O2 -D_FORTIFY_SOURCE=2 # Add canary code, i.e. detect buffer overflows
CFLAGS += -fstack-protector-all # Add canary code to detect stack smashing

LDFLAGS+= -lz


all: clean receiver sender

REC_OBJS = src/receiver.c src/utils.c src/pkt.c src/net.c
SEND_OBJS= src/sender.c src/utils.c src/pkt.c src/net.c

receiver:
	${CC} ${CFLAGS} ${REC_OBJS} -o receiver ${LDFLAGS}

sender:
	${CC} ${CFLAGS} ${SEND_OBJS} -o sender ${LDFLAGS}

test:
	@echo "\033[0;32mTesting with X delay\033[0m"	
	@./tests/test_linksim.sh
	@echo "\033[0;32mTesting transfer a file with size equal a packet\033[0m"
	@./tests/packet.sh
	@echo "\033[0;32mTesting transfer a file with size smaller than window\033[0m"
	@./tests/simple_file.sh
	@echo "\033[0;32mTesting transfer a file with size higher than window\033[0m"
	@./tests/big_file.sh
	@echo "\033[0;32mTesting decode a packet with his crc has changed\033[0m"
	${CC} ${CFLAGS} -I./src ./tests/bad_packet.c src/pkt.c -o bad_packet ${LDFLAGS}
	./bad_packet

.PHONY: clean test

clean:
	@rm -f receiver sender

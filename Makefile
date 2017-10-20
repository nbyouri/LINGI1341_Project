CC      = cc
CFLAGS += -g -Wall # Enable the 'all' set of warnings
#CFLAGS += -Werror # Treat all warnings as error
CFLAGS += -Wshadow # Warn when shadowing variables
CFLAGS += -Wextra # Enable additional warnings
CFLAGS += -O2 -D_FORTIFY_SOURCE=2 # Add canary code, i.e. detect buffer overflows
CFLAGS += -fstack-protector-all # Add canary code to detect stack smashing
#CFLAGS += -std=c99

LDFLAGS+= -lz


all: clean receiver sender

REC_OBJS = src/receiver.c src/utils.c src/pkt.c src/net.c src/min_queue.c
SEND_OBJS= src/sender.c src/utils.c src/pkt.c src/net.c src/min_queue.c

receiver:
	${CC} ${CFLAGS} ${REC_OBJS} -DPROGRAM_NAME=\"receiver\" -o receiver ${LDFLAGS}

sender:
	${CC} ${CFLAGS} ${SEND_OBJS} -DPROGRAM_NAME=\"sender\" -o sender ${LDFLAGS}

tests:
	@echo -ne "\033[0;32mTesting transfer a file with size equal a packet\033[0m\n"
	@./tests/packet.sh
	@echo -ne "\033[0;32mTesting transfer a file with size smaller than window\033[0m\n"
	@./tests/simple_file.sh
	@echo -ne "\033[0;32mTesting transfer a file with size higher than window\033[0m\n"
	@./tests/big_file.sh

# activate when selective repeat is functional
#@echo "\033[0;32mTesting with X delay\033[0m"	
#@./tests/test_linksim.sh

.PHONY: clean tests

clean:
	@rm -f receiver sender

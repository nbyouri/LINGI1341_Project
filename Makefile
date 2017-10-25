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

tests: all
	@echo -ne "\033[0;32mTesting transfer a file with size equal a packet\033[0m\n"
	@./tests/packet.sh
	@echo -ne "\033[0;32mTesting transfer a file with size smaller than window\033[0m\n"
	@./tests/simple_file.sh
	@echo -ne "\033[0;32mTesting transfer a file with size higher than window\033[0m\n"
	@./tests/big_file.sh
	@echo -ne "\033[0;32mTesting with some delay, loss, cut rate, error rate and jitter from receiver to sender\033[0m\n"
	@./tests/test_linksim.sh
	@echo -ne "\033[0;32mTesting with some delay, loss, cut rate, error rate and jitter from sender to receiver\033[0m\n"
	@./tests/test_linksim1.sh
	@echo -ne "\033[0;32mTesting with some delay, loss, cut rate, error rate and jitter bidirectional\033[0m\n"
	@./tests/test_linksim2.sh

archive:
	@zip project1_mouton_sias.zip receiver sender link_sim small_file Makefile medium_file big_file

.PHONY: clean tests

clean:
	@rm -f receiver sender

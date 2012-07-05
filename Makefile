CFLAGS += -std=c99 -O2 -g -Wall -Werror -pedantic
#CFLAGS += -DDEBUG
PROJECT= parade

all: $(PROJECT)

clean:
	rm -f $(PROJECT) *.o *.core

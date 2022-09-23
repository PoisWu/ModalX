

LINK_TARGET = tcp_hijack


OBJS = \
	tcp_hijack.o header.o dns.o
	


REBUILDABLES = $(OBJS) $(LINK_TARGET)

all : $(LINK_TARGET)


clean: 
	rm -f $(REBUILDABLES)


tcp_hijack : tcp_hijack.o header.o dns.o
	gcc -g  -o  $@ $^ -lpcap
	



%.o : %.c
	gcc -g   -Wall -o $@ -c $< 
  

Mingw -> gcc g++ 
 
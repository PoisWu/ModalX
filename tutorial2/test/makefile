
LINK_TARGET = test_client test_server write_file
all: $(LINK_TARGET)



test_client: test_client.o
	cc -g -o $@ $^

test_server: test_server.o
	cc -g -o $@ $^

%.o:%.c
	cc -g -Wall -o $@ -c $<

clean:
	rm -f $(LINK_TARGET) *.o write.txt

write_file:write_file.o
	cc -g -o $@ $^



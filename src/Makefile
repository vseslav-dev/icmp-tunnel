SOURCES		:= $(wildcard *.c)
OBJECTS		:= $(patsubst %c,%o,$(SOURCES))
DEPFILES	:= $(patsubst %.c,%.d,$(SOURCES))
#INC_DIR		:= include
#CFLAGS		+= -I../$(INC_DIR) 

INSTALL_DIR	:= /opt


$(PROG): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) 

%.o: %.d

%.d: %.c
	$(CC) $(CFLAGS) -MM -MT '$(patsubst %.c,%.o,$<)' $< -MF $@
	
ifeq (0, $(words $(findstring $(MAKECMDGOALS), clean print_vars cleanall)))
-include $(DEPFILES)
endif

.PHONY: install all
all:
	$(MAKE) $(PROG)

install: all
	install -c -m "u=rwxs,og=rxs" -o root -g root $(PROG) $(INSTALL_DIR)


.PHONY: cleanall clean
clean:
	rm -f $(OBJECTS) $(PROG) 

cleanall: clean
	rm -f $(DEPFILES)

.PHONY: print_vars
print_vars:
	@echo "===print_vars==="
	@echo "PROG		= $(PROG)"
	@echo "CFLAGS		= $(CFLAGS)"
	@echo "LDFLAGS		= $(LDFLAGS)"
	@echo "NODEP		= $(NODEP)"
	@echo "SOURCES		= $(SOURCES)"
	@echo "DEPFILES		= $(DEPFILES)"



export IF_DEBUG := true
export PROG	:= icmp-tunnel
SRC_DIR		:= ./src
export CC	:= gcc
ifeq ($(IF_DEBUG),true)
export CFLAGS := -Wall -Wextra -Wpedantic -DDEBUG -g -I../include
export LDFLAGS := -lefence -lm
else
PROC_FLAG := -march=znver1 -mtune=znver1 #processor specific flags
export CFLAGS := -Wall -Wextra -Wpedantic $(PROC_FLAGS) -O2 -I../include
export LDFLAGS := -lm
endif

.PHONY: all
all:
	$(MAKE) -C $(SRC_DIR) all

.PHONY: install
install:
	$(MAKE) -C $(SRC_DIR) install

.PHONY: clean
clean:
	$(MAKE) -C $(SRC_DIR) clean

.PHONY: cleanall
cleanall:
	$(MAKE) -C $(SRC_DIR) cleanall

.PHONY: print_vars
print_vars:
	@echo "===print_vars==="
	@echo "PROG		= $(PROG)"
	@echo "SRC_DIR		= $(SRC_DIR)"
	@echo "CFLAGS		= $(CFLAGS)"
	@echo "LDFLAGS		= $(LDFLAGS)"
	$(MAKE) -C $(SRC_DIR) print_vars


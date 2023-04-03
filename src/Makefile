CC	:= gcc
RM	:= rm
MV	:= mv
TARGET	:= libhooks.so
SUFFIX  := .c
CFLAGS  := -fPIC
TAR_DIR := ../bin/
INC_DIR	:= ../include
TOP_DIR	:= $(PWD)
TMP_DIR	:= $(TOP_DIR)/.tmp/
INC_DIR := $(realpath $(INC_DIR))
TAR_DIR := $(realpath $(TAR_DIR))
LIBS	  := -lrt -lconfig
SUB_DIR := vsftpd


export CC RM MV INC_DIR TOP_DIR TMP_DIR SUFFIX CFLAGS

all: CHECKDIR
	@$(foreach dir, $(SUB_DIR), \
		make -C $(dir);\
	)
	$(CC) $(LIBS) -shared -o $(TAR_DIR)/$(TARGET) $(TMP_DIR)*
	@rm -fr $(TMP_DIR)
	
CHECKDIR:
	@mkdir -p $(TMP_DIR)
clean:
	$(RM) $(TAR_DIR)/$(TARGET)


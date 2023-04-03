
TARGET  := $(basename $(TARGET))_mqs.o
SRCS    := $(wildcard *$(SUFFIX))
OBJS    := $(patsubst %$(SUFFIX), %.o, $(SRCS))

export TARGET

$(TARGET):
	@$(foreach obj, $(OBJS), \
		$(CC) $(CFLAGS) -I$(INC_DIR) -c $(basename $(obj))$(SUFFIX); \
	)
	@$(foreach obj, $(OBJS), \
		$(MV) $(obj) $(TMP_DIR)$(basename $(TARGET))_$(obj); \
	)

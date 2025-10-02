# Run inside the docker
ifeq ($(FLEX_SDK),)
$(error Environment variable FLEX_SDK is not set)
endif

mode = debug
target := $(shell uname -s)
variant = $(target)_$(mode)
o = target/$(variant)

test_files := $(wildcard *_test.c)
test_exes = $(patsubst %.c,$o/%,$(test_files))
test_oks = $(addsuffix .ok,$(test_exes))
mock_files = $(wildcard mock/*.c)
sdk_files = ${FLEX_SDK}/src/os_printf.c ${FLEX_SDK}/lib_standard_app/base58.c

all: $(test_oks) $(test_exes) $o/libsol.a

CFLAGS += -Werror -Wall -Wextra -pedantic -Wshadow -Wcast-qual -Wcast-align -Wno-unused-parameter -Wno-sign-compare
CFLAGS += -fPIC
CFLAGS += -Iinclude -Imock -I${FLEX_SDK}/include -I${FLEX_SDK}/io/include -I${FLEX_SDK}/target/flex/include/ -I${FLEX_SDK}/lib_standard_app/
CFLAGS += $($(mode)_CFLAGS)
# CFLAGS += -D PRINTF=mcu_usb_printf -D HAVE_PRINTF

ifeq ($(COVERAGE),1)
	CFLAGS += --coverage
endif

debug_CFLAGS = -g
release_CFLAGS = -O2

libsol_source_files = $(filter-out %_test.c,$(shell find . -name "*.c"))
libsol_object_files = $(patsubst %.c,$o/%.o,$(libsol_source_files))
libsol_depend_files = $(patsubst %.c,$o/%.d,$(libsol_source_files))

-include $(libsol_depend_files)

$o/%.o: %.c $(mock_files)
	@echo "==> Compile $<"
	@mkdir -p $(@D)
	$(CC) -MMD -c $(CFLAGS) $< -o $@

#
# unit tests
$o/%_test: $o/%_test.o $(sdk_files) $(mock_files) $o/libsol.a
	@echo "==> Link test $@"
	$(CC) $(CFLAGS) -o $@ $^

$o/%_test.ok: $o/%_test $(mock_files)
	@echo "==> Run test $<"
	@$<
	@touch $@


#
# libsol
#
$o/libsol.a: $(libsol_object_files)
	@echo "==> Create static library $@"
	ar rcs $@ $^

#
# clean
#
.PHONY: clean
clean:
	@echo "==> Clean build directory"
	rm -rf target

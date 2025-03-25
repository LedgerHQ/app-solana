mode = debug
target := $(shell uname -s)
variant = $(target)_$(mode)
o = target/$(variant)

test_files := $(wildcard *_test.c)
test_exes = $(patsubst %.c,$o/%,$(test_files))
test_oks = $(addsuffix .ok,$(test_exes))

all: $(test_oks) $(test_exes) $o/libsol.a

CFLAGS += -Werror -Wall -Wextra -pedantic -Wshadow -Wcast-qual -Wcast-align -Wno-unused-parameter
CFLAGS += -fPIC
CFLAGS += -Iinclude -Imock
CFLAGS += $($(mode)_CFLAGS)

ifeq ($(COVERAGE),1)
	CFLAGS += --coverage
endif

debug_CFLAGS = -g
release_CFLAGS = -O2

libsol_source_files = $(filter-out %_test.c,$(shell find . -name "*.c"))
libsol_object_files = $(patsubst %.c,$o/%.o,$(libsol_source_files))
libsol_depend_files = $(patsubst %.c,$o/%.d,$(libsol_source_files))

-include $(libsol_depend_files)

$o/%.o: %.c
	@echo "==> Compile $<"
	@mkdir -p $(@D)
	$(CC) -MMD -c $(CFLAGS) $< -o $@

#
# unit tests
#
# Note: this executes on the host, not via QEMU
$o/%_test.ok: $o/%_test
	@echo "==> Run test $<"
	@$<
	@touch $@

$o/%_test: $o/%_test.o $o/libsol.a
	@echo "==> Link test $@"
	$(CC) $(CFLAGS) -o $@ $^

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

# Run inside the docker
ifeq ($(FLEX_SDK),)
$(error Environment variable FLEX_SDK is not set)
endif

mode = debug
target := $(shell uname -s)
variant = $(target)_$(mode)
o = target/$(variant)

# Verbosity control
#
# Default        : concise build progress ("==> Compile foo.c") plus the full
#                  per-test-case output of every test suite.
# make VERBOSE=1 : verbose, also echo the full compiler/linker command lines.
# make QUIET=1   : quiet, hide build progress and the per-test-case chatter, but
#                  still report one "PASS <suite>" line per test executable.
#
# cmd_prefix    : prefixed to raw commands (@ hides them, empty echoes them).
# progress      : prints the build "==>" progress lines (echo or no-op).
# test_redirect : appended to a test run to drop its per-case stdout in quiet mode.
# test_report   : prints the per-suite "PASS" line (only meaningful in quiet mode,
#                 since the full output already shows results otherwise).
cmd_prefix = @
progress = @echo
test_redirect =
test_report = @:
ifeq ($(VERBOSE),1)
	cmd_prefix =
endif
ifeq ($(QUIET),1)
	progress = @:
	test_redirect = >/dev/null
	test_report = @echo
endif

test_files := $(wildcard *_test.c)
test_exes = $(patsubst %.c,$o/%,$(test_files))
test_oks = $(addsuffix .ok,$(test_exes))
mock_files = $(wildcard mock/*.c)
sdk_files = ${FLEX_SDK}/src/os_printf.c ${FLEX_SDK}/lib_standard_app/base58.c

# Keep intermediate object files: avoids the noisy automatic "rm ..." line and
# speeds up incremental rebuilds.
.SECONDARY:

all: $(test_oks) $(test_exes) $o/libsol.a

#
# Report tests that are already up-to-date and will therefore not be re-run.
# report_skipped is an order-only prerequisite of every .ok target (see below),
# so it runs after the test executables are (re)built but before any test is
# executed. A test's .ok sentinel being newer than its executable means the
# test will not be re-run this invocation, so we print SKIPPED for it. This
# prints all SKIPPED lines as one block first, then the per-suite pass/fail
# output follows as the out-of-date tests actually run.
.PHONY: report_skipped
report_skipped: $(test_exes)
	@for test_exe in $(test_exes); do \
		if [ -e "$$test_exe.ok" ] && [ "$$test_exe.ok" -nt "$$test_exe" ]; then \
			echo "SKIPPED $$(basename $$test_exe)"; \
		fi; \
	done

CFLAGS += -Werror -Wall -Wextra -pedantic -Wshadow -Wcast-qual -Wcast-align -Wno-unused-parameter -Wno-sign-compare
CFLAGS += -fPIC
CFLAGS += -Iinclude -Imock -I${FLEX_SDK}/include -I${FLEX_SDK}/io/include -I${FLEX_SDK}/target/flex/include/ -I${FLEX_SDK}/lib_standard_app/
CFLAGS += -isystem /usr/include/bsd -DLIBBSD_OVERLAY
LDFLAGS += -lbsd
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
	$(progress) "==> Compile $<"
	@mkdir -p $(@D)
	$(cmd_prefix)$(CC) -MMD -c $(CFLAGS) $< -o $@

#
# unit tests
$o/%_test: $o/%_test.o $(sdk_files) $(mock_files) $o/libsol.a
	$(progress) "==> Link test $@"
	$(cmd_prefix)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$o/%_test.ok: $o/%_test $(mock_files) | report_skipped
	$(progress) "==> Run test $<"
	@$< $(test_redirect)
	$(test_report) "PASS $(notdir $<)"
	@touch $@


#
# libsol
#
$o/libsol.a: $(libsol_object_files)
	$(progress) "==> Create static library $@"
	$(cmd_prefix)ar rcs $@ $^

#
# clean
#
.PHONY: clean
clean:
	$(progress) "==> Clean build directory"
	$(cmd_prefix)rm -rf target

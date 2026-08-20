cmake_minimum_required(VERSION 3.20)

project(SolanaAppFuzzer
        VERSION 1.0
        DESCRIPTION "Ledger Solana App Fuzzer"
        LANGUAGES C)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined")
endif()

# Exports the `secure_sdk` target and ledger_fuzz_add_app_target().
include(${BOLOS_SDK}/fuzzing/cmake/LedgerAppFuzz.cmake)
ledger_fuzz_setup()

set(APP_SOURCE_DIR ${CMAKE_SOURCE_DIR}/..)

file(GLOB_RECURSE C_SOURCES CONFIGURE_DEPENDS
    ${APP_SOURCE_DIR}/src/*.c
    ${APP_SOURCE_DIR}/libsol/*.c
    ${CMAKE_SOURCE_DIR}/mock/*.c)
# libsol/mock/ shadows SDK headers for the standalone test suite. src/ui/ holds
# NBGL callbacks whose file-scope enum globals clang narrows, so the declared and
# runtime sizes disagree and sample_invariant() reports spurious overflows;
# mock/mocks.c stubs the entry points so handlers still link.
list(FILTER C_SOURCES EXCLUDE REGEX ".*/libsol/.*_test\\.c$")
list(FILTER C_SOURCES EXCLUDE REGEX ".*/libsol/mock/.*")
list(FILTER C_SOURCES EXCLUDE REGEX ".*/src/ui/.*")
list(REMOVE_ITEM C_SOURCES ${APP_SOURCE_DIR}/src/main_application.c)

ledger_fuzz_collect_include_dirs(APP_INCLUDE_DIRS
    ${APP_SOURCE_DIR}/src
    ${APP_SOURCE_DIR}/libsol)
list(FILTER APP_INCLUDE_DIRS EXCLUDE REGEX ".*/libsol/mock$")
list(APPEND APP_INCLUDE_DIRS
    ${APP_SOURCE_DIR}/libsol/include
    ${BOLOS_SDK}/lib_standard_app
    ${BOLOS_SDK}/lib_tlv
    ${BOLOS_SDK}/lib_tlv/use_cases
    ${CMAKE_SOURCE_DIR}/mock
    ${CMAKE_SOURCE_DIR})

# HAVE_* / APPNAME / ... arrive transitively from secure_sdk
# (make list-defines + macros/add_macros.txt).
ledger_fuzz_add_app_target(
    NAME fuzz_app
    SOURCES ${C_SOURCES} ${LEDGER_FUZZ_TLV_MUTATOR_SOURCE}
    INCLUDE_DIRECTORIES ${APP_INCLUDE_DIRS})

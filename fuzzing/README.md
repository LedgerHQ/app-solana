# Solana app fuzzing

Absolution-based, coverage-guided fuzzing for the Solana app, built on the Ledger
SDK fuzzing framework.

**Read the framework documentation first.** Concepts (what a corpus is, how the
`[ prefix | tail ]` input works, the manifest, invariants, mocks, harnesses, the
CMake API, CI, and how to maintain it) live in the **Fuzzing Framework** page of
the SDK documentation, published at
<https://ledgerhq.github.io/ledger-secure-sdk/>. This file documents only what is
specific to the Solana app.

## Quickstart

```bash
export BOLOS_SDK=/opt/flex-secure-sdk
"$BOLOS_SDK"/fuzzing/scripts/app-campaign.sh --app-dir "$(pwd)" my-campaign
```

Outputs land in `.fuzz-artifacts/<name>/`. Omit the name for a UTC timestamp.
Select the sanitizer with **`APP_SANITIZER`** (`address`, `undefined`, `memory`) —
not `SANITIZER`, which the campaign script does not read.

## Target

One target, `fuzz_app`. An input drives a single APDU through the real
`apdu_handle_message()` → handler switch, so every instruction in
`fuzz_commands[]` is reachable, and a P1 control byte >= 224 diverts to a
swap-callback lane instead.

That lane exists because `check_address`, `get_printable_amount` and
`copy_transaction_parameters` are entered from the Exchange app as library calls,
never through an APDU, so no fuzzed APDU can reach them.

`fuzz-manifest.toml` is the authoritative list of the target, seeds, dictionary
and coverage key files.

## What the harness owns, and what it must not

The harness owns **structure** and never authors **content**: it frames APDUs and
sizes buffers, while every byte inside them comes from the fuzzer.

Two consequences are easy to get wrong.

**Heap-owned globals are reset, not freed.** `G_preview_state`, `g_trusted_info`
and `g_dynamic_token_info` are allocated with `APP_MEM_CALLOC` and freed through
`APP_MEM_FREE_AND_NULL`. Listing them in `invariants/zero-symbols.txt` constrains
the mutator, but the prefix is still copied into the global verbatim, so an
arbitrary value can reach them. `fuzz_app_reset()` therefore assigns NULL rather
than calling the app's reset helpers: those free, and `mem_free()` dereferences
the pointer as a chunk header before it can reject it.

**The memory pool is re-initialised every iteration.** `app_mem_init()` is called
from `main_application.c` on device, and that file is excluded here. Without the
call every `APP_MEM_CALLOC` fails and the handlers behind those globals never
run. Re-initialising also reclaims the previous iteration's blocks, which the
NULLs above have just orphaned.

**Swap buffers follow the app's size contract.** `destination_address_extra_id`
carries no length field: `swap_copy_transaction_parameters()` reads type,
template id and tx hash at fixed offsets and documents the minimum Exchange
guarantees. `SWAP_SCRATCH_EXTRA_ID` is bound to
`EXTRA_ID_SOLANA_TEMPLATE_MIN_SIZE` so an undersized buffer cannot make the app's
read look like an app bug.

## TLV grammars

Three instructions carry TLV payloads — `ProvideInstructionDescriptor`,
`ProvideInfo` and `ProvideDynamicDescriptor`. Each has a tag table in
`harness/fuzz_dispatcher.c` derived from the handler's X-macros and the SDK
`lib_tlv` use-case files, and `fuzz_tlv_dispatch_mutate()` uses it to generate
structurally valid tag-length-value streams instead of random bytes. Byte 1 of
the harness input picks which table applies.

## Excluded from the build

`src/ui/` is dropped on purpose. Its NBGL callbacks are pure rendering, and its
file-scope globals get narrowed by clang's GlobalOpt pass when only enum or bool
values are assigned to them; Absolution records the declared size, the narrowed
runtime size no longer matches, and the mismatch surfaces as spurious global
buffer overflows. Stubbed entry points live in `mock/mocks.c` so handlers that
reach a UI boundary still link.

`main_application.c` is excluded as the hardware entry point, and `libsol/mock/`
because it shadows SDK headers for libsol's standalone test suite.

## App-owned files in this tree

```text
fuzzing/
  fuzz-manifest.toml        target, seeds, dictionary, coverage key files
  base-corpus.zip           promoted corpus (+ base-corpus.compat-key sidecar)
  harness/fuzz_dispatcher.c APDU serialiser, swap lane, TLV grammars
  mock/                     UI stubs, ATA bypass, crypto and state restore
  invariants/               zero-symbols.txt, domain-overrides.txt
  macros/                   add_macros.txt, exclude_macros.txt
  scripts/                  generate_custom_seeds.py
  seeds/raw-transactions/   50 curated transactions kept from the previous fuzzer
```

The seed script wraps each recorded transaction in a SignMessage APDU and writes
nothing else: no length or count is computed, so the fuzzer stays free to make
any of them inconsistent. Seeds are the cold-start floor under
`base-corpus.zip`, not an addition to it — with the corpus present they measure
as noise.

Dictionary entries earn their place by being bytes the fuzzer cannot reach
otherwise. Keep them **multi-byte and distinct**: `ChangeByte` already covers
every single byte for free, libFuzzer picks uniformly from a flat vector so a
repeated value only dilutes the pool, and CLA/INS/P1/P2 never appear in the tail
at all because `serialise_apdu()` writes them from `fuzz_commands[]`. The
32-byte program ids are the entries that matter: `instruction_program_id()`
memcmp's all 32, which no mutation will produce by chance.

`invariants/fuzz_globals.zon` is generated per build and gitignored: it records
absolute source paths, so committing it makes the corpus compat key depend on
where the SDK was mounted.

## Maintenance

1. **Add an instruction** — append to `fuzz_commands[]`, and add a matching
   `tlv_configs[]` entry (`{0}` if it carries no TLV); the array is indexed by
   position in `fuzz_commands[]`.
2. **Add a TLV tag** — extend the matching tag table; keep it aligned with the
   handler's X-macro list.
3. **Add or remove an app global** — constrain it in `invariants/zero-symbols.txt`
   or `invariants/domain-overrides.txt`. Domain-override keys are
   `<global>.<field>` with **no** `@file` suffix, unlike zero-symbols, which does
   take `@file.c` to disambiguate statics. A build reports entries that match
   nothing; treat that as an error to fix rather than noise.
4. **Re-promote the corpus** — after any change to the prefix layout, the SDK
   version or `harness_version`. Promote from a build inside the CFL image, since
   the compat key hashes the discovered invariant and so is tied to the SDK the
   build used; a corpus promoted from a local campaign is rejected by CI.

## Known reports

`libsol/printer.c:157` (`while (zero_count-- > 0)`) reports an unsigned wrap on
its final test. Unsigned overflow is defined to wrap, the loop exits correctly,
and the wrapped value is never read, so it is left alone; the sanitizer is
configured to recover from it.

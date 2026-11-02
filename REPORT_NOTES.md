# Report notes

## Algorithms and sources

- **SPECK128/128:** 128-bit blocks, a 128-bit key and 32 rounds. `speck128.c`
  adapts the designers' algorithm and reference routines using named functions.
  The round keys and block known answer in `test_speck128.c` come from sections
  6 and 16 of Beaulieu et al., *SIMON and SPECK Implementation Guide*,
  15 January 2019:
  <https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf>.
- **Trivium:** 80-bit key, 80-bit IV, 288 state bits and 1,152 initialization
  steps. The initial core was written from the designers' equations. On
  2 November 2026 its clock-step layout was adapted to Wu Han's MIT-licensed
  C implementation, with the full notice retained in `THIRD_PARTY_NOTICES.md`:
  <https://github.com/wuhanstudio/trivium/blob/b8bc30f412c4c9cf3d8ea0c7ed1755be577ebdd1/trivium-c/trivium.c>.
  The original specification remains section 6.7 of Christophe De Canniere's
  2007 thesis:
  <https://cosicdatabase.esat.kuleuven.be/backend/publications/files/these/139>.
- Trivium expected outputs are from the ECRYPT Stream Cipher Project's 80/80
  vectors, sets 1, 2, 5 and 6, vector 0, preserved at:
  <https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/trivium-80.80.test-vectors>.
  Only vector data is used from this repository; no cipher implementation code
  was imported from it.

Retain these attributions in the final report, alongside the references in the
source. A report-ready historical OpenSSL eligibility audit remains to be done.

## SPECK byte order and decryption

The designers' guide represents a block as two little-endian 64-bit words: the
first eight bytes are `y`, the next eight `x`. Explicit byte loads/stores avoid
depending on machine endianness or casting potentially unaligned byte buffers
to word pointers.

Key expansion reuses the round function and produces 32 round keys. Decryption
reverses the round operations, replaces addition with subtraction, and applies
the round keys in reverse order. The tests check all 32 published keys and
independently check encryption and decryption against the published block pair.

## Trivium serialization mismatch and fix

The first implementation's bit/byte mapping did not match the selected vector
collection. The single-key-bit test produced `ba` as its first byte instead of
the published `38`.

The state-update equations were retained. Initialization was corrected to read
key and IV bytes from index 9 down to 0, most-significant bit first within each
byte. Thus `state[0]` receives bit 7 of `key[9]`. Output was corrected so the
first generated bit occupies bit 0 of the first output byte. Together these
conventions match the cited ECRYPT 80/80 vectors and are retained by the provider.

An all-zero key/IV cannot establish input bit order. Validation therefore also
uses single-key-bit, single-IV-bit and mixed-key/IV known answers, plus published
later windows around 64 KiB and 128 KiB.

## State and buffer handling

Trivium stores each state bit as one byte to make the equations easy to follow.
All feedback is computed before the state is shifted. The original three
`memmove` calls were replaced on 2 November 2026 with an explicit descending
loop, followed by writes to the first position of each register. This follows
the layout of Wu Han's `trivium_rotate`, using one array element per bit
instead of packed bits. This implementation favors clarity over speed; that
choice should be discussed in the benchmark results.

Successive calls continue the stream. A context copy provides an independent
continuation because the context owns all of its state directly. Reinitializing
resets the state and output counter. Requests exceeding 2^64 keystream bits are
rejected without modifying the context or output.

Both cores support exact in-place operation. Partial buffer overlap is outside
their API contract. External key/IV lengths are checked by the provider.

## Validation performed

The assistant ran standalone checks separately from the normal CMake build.
On 1 November 2026, the five `test_` files were removed at the user's request:
they are not dependencies of the provider or its build. The results below
describe validation completed before their removal. The runnable repository
contains the provider sources, build configuration and usage instructions.

- SPECK: published block encryption/decryption, all 32 published round keys,
  in-place and unaligned buffers, and 256 additional key/block round trips.
- Trivium: four published first-keystream vectors, all 65 split points in a
  64-byte known answer, later keystream windows, chunked encryption/decryption,
  in-place processing, empty calls, context copies, reset and limit rejection.
- On 1 November 2026, checks passed with GCC 14.2.0 in the original Debug,
  Release and address/undefined-behavior sanitizer builds. The sanitizer run
  also passed with leak detection enabled outside the restricted environment.

The directory refactor moves these same cores and test sources to the project
root. After the refactor, the default CMake build completed without warnings;
both test suites were compiled separately against the resulting
`libcipher_cores.a` and all checks passed. Temporary test executables were placed
under `/tmp`, outside the project directory.

## Provider and mode integration

`ca.so` is a dynamically loadable provider. `provider.c` advertises four cipher
names through `OSSL_OP_CIPHER`: `SPECK128-128-ECB`, `SPECK128-128-CBC`,
`SPECK128-128-CTR` and `TRIVIUM`. The original OpenSSL executable is used without
modification. Provider metadata, query and cipher callbacks follow the public
[provider-base](https://docs.openssl.org/3.5/man7/provider-base/) and
[provider-cipher](https://docs.openssl.org/3.5/man7/provider-cipher/) APIs.
The adapter code is original project code; it does not import another provider.

`provider_cipher.c` shares lifecycle, parameter and buffering code between the
algorithms. An immutable specification provides mode, key length, IV length and
the EVP block size. ECB/CBC report a 16-byte block; CTR and Trivium report a
one-byte processing unit so EVP accepts arbitrary input lengths. All modes
validate fixed key/IV sizes. Context duplication copies all buffered state,
and freeing a context clears its allocated key/state memory.

EVP permits staged initialization: selecting an algorithm, supplying a key and
supplying an IV may happen in separate calls. The adapter therefore tracks
which required inputs are available and rejects data processing until ready.
Reinitialization with NULL key/IV retains the configured values, restores the
original IV and resets buffering. Finished or failed operations require
reinitialization before another update.

### Partial blocks and padding

ECB/CBC retain incomplete input across updates. PKCS#7 padding is enabled by
default; `-nopad` disables it and requires a complete final block. Encryption
of an aligned input adds a full padding block, including for empty plaintext.
Padded decryption keeps the final ciphertext block until `final`, checks every
padding position and returns only the unpadded bytes. Invalid padding and
incomplete ciphertext are errors.

When input and output are the same buffer, pending bytes can cause output to
overtake unread input. The adapter copies that call's input only when there is
already buffered input and exact in-place processing was requested. This
preserves correctness without making a copy for ordinary calls.

Output capacity is checked before processing. Padded decryption checks its
final block using a temporary state copy, so insufficient final output space
can be retried without losing CBC state. Parameters can be queried without
changing state; padding must be configured before supplying data.

### CTR convention and exhaustion

CTR treats all 16 IV bytes as one **big-endian 128-bit counter**. It encrypts
the current counter, increments it from byte 15 toward byte 0, and consumes the
generated keystream across update boundaries. This counter convention is
independent of SPECK's little-endian conversion inside a block.

A request is checked against counter wrap before any output or state change.
The all-ones counter block can be consumed, including cached remaining bytes,
but another counter block is rejected. Original-IV and updated-IV queries
report the initial value and next counter respectively.

### CLI ECB initialization failure and fix

The first CLI run failed with `incorrect IV length` for ECB, despite ECB having
no IV. OpenSSL's generic callers can supply a non-NULL IV pointer with a length
of zero. The adapter initially rejected that combination. It now ignores the
pointer when the expected and supplied lengths are both zero, and continues
to reject nonzero IV lengths for ECB. A direct-callback regression covers this.

### Benchmark setup failure and fix

The first `openssl speed` call loaded only `ca`. The command could not fetch
`CTR-DRBG` to generate random test keys. Loading both the **default** provider
and **ca** supplies the RNG while the uniquely named ciphers are fetched from
our provider. No RNG implementation is added to `ca`.

### Known answers for the modes

Let `(P, C)` be the designers' published SPECK block pair, with `E(P) = C` under
the published key. The mode tests derive answers algebraically:

- ECB directly checks the published pair in both directions.
- CBC chooses first plaintext block `P XOR IV` and second plaintext block
  `P XOR C`. CBC must produce `C` twice: both inputs to `E` are exactly `P`.
- CTR uses `P` as its initial counter and encrypts a zero block. The expected
  keystream/ciphertext is `C`.
- Trivium through EVP checks the ECRYPT 80/80 set 1, vector 0 keystream.

Thus the CBC/CTR mode answers are derived and justified from a published core
answer, rather than obtained by round-tripping the mode implementation. A
separate CTR carry test checks successive known counter blocks against the
validated core and checks the updated IV.

### Provider validation results

On 1 November 2026, with GCC 14.2.0 and OpenSSL 3.5.7:

- Provider loading and algorithm listing succeeded with the installed CLI.
- EVP tests passed known answers for all four algorithms; all input sizes
  0 through 81 with applicable padding settings and six update chunk sizes;
  both directions; copied contexts; and chunked in-place operation.
- Malformed padding, incomplete `-nopad` blocks, incorrect parameter sizes and
  types, absent initialization data, insufficient output space, update after
  final and CTR wrap were checked. Output-space retries and staged/key-retaining
  initialization passed. The raw `EVP_Cipher` interface was checked separately
  because it must bypass padding even when padding is enabled for update/final.
- `test_cli.sh` passed **78 file encryption/decryption round trips**, covering
  empty, 1, 15, 16, 17, 31, 32, 33, 256, 4096 and 1,048,576-byte files, with
  padding and applicable `-nopad` combinations. Malformed padding and truncated
  ciphertext were also rejected by the CLI.
- Original standalone core suites still passed.
- The provider and EVP checks also passed AddressSanitizer,
  UndefinedBehaviorSanitizer and leak detection, with temporary builds under
  `/tmp` rather than adding project build directories.
- All four algorithms completed one-second `openssl speed -evp` compatibility
  runs at 1024 bytes. These were smoke checks, **not the final comparative
  benchmarks**.

Historical OpenSSL eligibility evidence, the final benchmark comparisons and
the written report remain.

## Minimal repository validation

On 1 November 2026, a clean temporary directory containing only the seven
provider/core source and header files, `CMakeLists.txt`, `README.md` and
`.gitignore` configured and built successfully without warnings. Provider
loading and all four algorithm listings passed. The existing standalone core,
EVP and CLI checks were run from temporary copies outside the project; all
passed, including the 78 CLI file round trips and invalid-input checks.
No test source is needed to build or load the provider. Generated build files,
manual sample files, the assignment PDF and working documents are not part
of the minimal repository.

## Reference-based simplification, 2 November 2026

The changes were initially kept local and are now included in the repository.

SPECK uses the designers' reference C routines in sections 1 and 6 of the
2019 guide. The local named functions expand the guide's `ER64` and `DR64`
macros into separate statements. The key schedule now stores `A` before
each round and stores the final key after the loop, matching
`Speck128128KeySchedule`. The designers' repository publishes its work under
[CC0](https://github.com/nsacyber/simon-speck/blob/master/LICENSE.md).

Trivium now follows the clock-step layout in Wu Han's C implementation at
commit `b8bc30f412c4c9cf3d8ea0c7ed1755be577ebdd1`, source blob
`9909a9e023cbc8794847522b95329bb88cacb340`.
The copyright and complete MIT licence notice are included in `THIRD_PARTY_NOTICES.md`.

| Local function | Reference correspondence and adaptation |
| --- | --- |
| `trivium_clock` | `trivium_rotate`: calculate taps, output and feedback, shift, then insert the three new bits. The local array stores one bit per element, so it uses direct indexes and an ordinary descending copy loop. |
| `trivium_next_byte` | `trivium_gen_keystream`: clock eight times and put the first generated bit in bit 0. |
| `trivium_init` | `trivium_init` and `trivium_init_state`: load key/IV, set the last three bits and discard 1,152 output bits. The local API initializes a caller-owned context. |
| `trivium_generate`, `trivium_crypt` | Local buffer interfaces, accounting and XOR around that clock step. |

Wu Han's version reads the first key/IV byte first, high bit first. This
project preserves its existing ECRYPT 80/80 serialization: last byte first,
high bit first. Differential tests therefore reverse the ten key and IV
bytes before passing them to the upstream implementation. No output-byte
reversal is needed. This distinction matters for nonzero test vectors.

Suggested report wording: "The SPECK core adapts the designers' published C
reference routines. The Trivium clock-step structure adapts Wu Han's
MIT-licensed C implementation, using a byte per state bit and the project's
documented ECRYPT serialization. These cores are integrated with our OpenSSL
provider callbacks, modes, buffering and parameter handling."

Validation completed after the changes, with temporary check sources and
executables under `/tmp`:

- Warning-free CMake build.
- SPECK's published block answer in both directions; all round keys and
  ciphertext compared with the prior implementation for 256 keys/blocks.
- Four published Trivium vectors and all 65 two-call split points in a
  64-byte answer.
- Trivium output and state matched the previous core; output also matched
  Wu Han's actual C implementation for 32 varied key/IV pairs.
- Chunked and in-place processing, reset, context copies, empty calls and
  the keystream-limit boundary passed.
- EVP fetched all four algorithms; provider context duplication passed for
  each, including a Trivium known answer through EVP.
- 78 CLI round trips, from empty to 1 MiB inputs, passed. Ciphertext with
  default padding matched the previous provider at every tested length.
  Invalid padding, truncated ciphertext and incomplete `-nopad` blocks
  were rejected.
- The existing `input.txt` passed binary and Base64 round trips for all four
  algorithms. The five sample files were preserved.
- AddressSanitizer, UndefinedBehaviorSanitizer and leak detection passed
  for the core/EVP checks and the instrumented provider.
- All four algorithms passed one-second `openssl speed` smoke runs at
  1024-byte buffers.

The explicit Trivium shift loop has a substantial performance cost in the
current build, which has no optimization flag. A one-second, 1024-byte
speed check measured approximately 4.38 MB/s for the previous provider and
0.244 MB/s for the explicit-loop version, about 18 times slower. These are
diagnostic smoke measurements, not the final comparative benchmarks. The
loop copies 287 state elements for every generated bit; the prior version
used optimized library `memmove` calls. The simplification changes how the
state is moved, not the resulting cipher stream. Future benchmark results
must identify which implementation and compiler flags were used.

Build and file-operation diagrams, function responsibilities and the
encryption/decryption distinction are in [FLOW.md](FLOW.md).

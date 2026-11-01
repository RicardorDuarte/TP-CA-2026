# OpenSSL provider project

Two-person Applied Cryptography project using **SPECK128/128** and **Trivium**.
The goal is a provider loaded by the standard, unmodified `openssl` command.
This repository contains the source and instructions needed to build and use it.

The provider implements SPECK ECB/CBC/CTR and Trivium, including streaming,
padding and context duplication. Loading, known answers, CLI file operations
and compatibility with `openssl speed` have been checked. Final comparative
benchmarks, historical eligibility evidence and the report remain.

## Build

From this directory:

```sh
cmake .
cmake --build .
```

The first command configures the build; the second compiles the project.
The outputs are `ca.so` (the provider) and `libcipher_cores.a` (the standalone
cores). A C compiler, CMake, a build tool such as Make, the OpenSSL 3 command,
development headers and libcrypto are required. Use the
installed compiler's default C language mode; no Debug/Release selection or
additional build directories are needed.

## Use with OpenSSL

```sh
openssl list -provider-path . -provider ca -providers
openssl list -provider-path . -provider ca -cipher-algorithms -propquery provider=ca
```

| Algorithm name | Key | IV | Padding |
| --- | --- | --- | --- |
| `SPECK128-128-ECB` | 16 bytes | None | PKCS#7, or `-nopad` |
| `SPECK128-128-CBC` | 16 bytes | 16 bytes | PKCS#7, or `-nopad` |
| `SPECK128-128-CTR` | 16 bytes | 16 bytes | None |
| `TRIVIUM` | 10 bytes | 10 bytes | None |

Example CBC encryption and decryption, using explicit hexadecimal test key/IV
values and an existing `input.txt`:

```sh
openssl enc -provider-path . -provider ca -SPECK128-128-CBC \
  -K 000102030405060708090a0b0c0d0e0f -iv 101112131415161718191a1b1c1d1e1f \
  -in input.txt -out ciphertext.txt

openssl enc -d -provider-path . -provider ca -SPECK128-128-CBC \
  -K 000102030405060708090a0b0c0d0e0f -iv 101112131415161718191a1b1c1d1e1f \
  -in ciphertext.txt -out recovered.txt
```
Example CTR using -nopad
```sh
openssl enc -d -provider-path . -provider ca -SPECK128-128-CTR -nopad   \
-K 000102030405060708090a0b0c0d0e0f   -iv 101112131415161718191a1b1c1d1e1f \
-a -in encrypted.txt -out recovered.txt

```

Example Trivium encryption and decryption:

```sh
openssl enc -provider-path . -provider ca -TRIVIUM \
  -K 00010203040506070809 -iv 10111213141516171819 \
  -in input.txt -out ciphertext.txt

openssl enc -d -provider-path . -provider ca -TRIVIUM \
  -K 00010203040506070809 -iv 10111213141516171819 \
  -in ciphertext.txt -out recovered.txt
```

Compare the recovered file with the original using `cmp input.txt recovered.txt`.

For `openssl speed`, load both `-provider default` and `-provider ca`: the
default provider supplies the benchmark's random-key generation.

```sh
openssl speed -provider-path . -provider default -provider ca -evp TRIVIUM
openssl speed -provider-path . -provider default -provider ca -evp SPECK128-128-CTR
```

## Files

- `speck128.c`, `speck128.h`: key expansion and block encryption/decryption.
- `trivium.c`, `trivium.h`: initialization, keystream and streaming XOR.
- `provider.c`: module entry point, metadata and algorithm registration.
- `provider_cipher.c`, `provider_cipher.h`: callbacks, modes, buffering and
  parameters connecting the cores to OpenSSL.
- `CMakeLists.txt`: build configuration.
- `.gitignore`: excludes generated build files from version control.

# wolfCert Zephyr module

Zephyr integration for wolfCert. For what the library does and how its API
works see the top-level `README.md`, `docs/ARCHITECTURE.md` and the headers in
`wolfcert/`. This file covers only what is specific to building it under
Zephyr.

Only the client runs on target. wolfCert's in-tree test server drives sockets
directly rather than going through `WolfCertTransport`, so no Zephyr image
builds it; the on-target tests enrol against `wolfcert-server` on the host.

## Requirements

- Zephyr **v4.4.2** or newer and its matching SDK (v4.4.2 pins 1.0.1).
- wolfSSL from **master**: wolfCert calls `wc_SetDNSEntry()` and
  `wc_SetAltNamesFromList()`, which are not in the v5.9.2 release.

## Adding wolfCert to a west workspace

```yaml
manifest:
  remotes:
    - name: wolfssl
      url-base: https://github.com/wolfssl

  projects:
    - name: wolfssl
      path: modules/crypto/wolfssl
      revision: master
      remote: wolfssl
    - name: wolfCert
      path: modules/lib/wolfcert
      revision: main
      remote: wolfssl
```

To build from a local checkout without touching the manifest:

```sh
west build -b qemu_x86 <app> -- -DEXTRA_ZEPHYR_MODULES=/path/to/wolfCert
```

## Configuration

`CONFIG_WOLFCERT=y` enables the library; set `CONFIG_WOLFSSL=y` with it.
`menuconfig` lists the rest under **wolfCert Support**. The module renders
`wolfcert/options.h` from those symbols at build time, so a Zephyr build needs
no `user_settings.h`.

Three things the Kconfig does that are worth knowing:

- **It supplies wolfSSL's configuration.** `zephyr/wolfssl_user_settings.h` is
  used unless the application sets `CONFIG_WOLFSSL_SETTINGS_FILE` itself. The
  wolfSSL module's own defaults do not satisfy `wolfcert/check_config.h`.
- **It selects `NETWORKING` and `POSIX_API`**, even for an image that opens no
  socket: wolfSSL needs `clock_gettime` from one and the `AF_INET` definitions
  its `OPENSSL_EXTRA` x509 code uses from the other.
- **`CONFIG_WOLFCERT_POSIX_STORE` is off by default.** Use the in-memory
  backend, or write a `WolfCertStoreOps` over NVS or the settings subsystem.

## The `connect` and `accept` macros

On Zephyr `wolfssl/wolfcrypt/settings.h` turns `connect` and `accept` into
macros for `zsock_connect` / `zsock_accept`. wolfCert has a public struct
member of each name, so the preprocessor renames those too.

**Applications need to do nothing.** `<wolfcert/wolfcert.h>` reaches wolfSSL's
settings before it declares the members, so the declaration and your use of it
are renamed together and agree. This holds whichever order you include the two
headers in.

**Do not `#undef connect` or `#undef accept` in application code.** That leaves
your code asking for `connect` while the member is declared `zsock_connect`:

```
error: 'WolfCertTransport' has no member named 'connect'
```

`src/internal.h` does undef them, because wolfCert's own sources reach
`wolfcert/types.h` before any wolfSSL header and so need the opposite. Only
the field name is affected, never the layout, so a prebuilt library links
either way.

## Sizing

See `docs/EMBEDDED.md` section 8. The short version: build with
`CONFIG_HW_STACK_PROTECTION=y` while tuning `CONFIG_MAIN_STACK_SIZE`, because
a stack overflow here is reported as something else entirely.

## Sample

`samples/wolfcert_est_client/` — EST enrollment against a host server. Its
README covers running and adapting it.

## Running the tests

```sh
west twister -T <wolfcert>/zephyr/tests -p qemu_x86 \
    -x=EXTRA_ZEPHYR_MODULES=/path/to/wolfCert
```

A networked QEMU image defaults to SLIP and waits forever on `/tmp/slip.sock`.
The unit tests set `CONFIG_NET_TEST=y` to suppress that. An image that really
needs the network sets `CONFIG_NET_QEMU_USER=y` (SLIRP), which reaches the host
at `10.0.2.2` and needs no TAP device or root.

It does need a QEMU with the SLIRP backend, which the Zephyr SDK's build does
not link. Use the distribution's and point Zephyr at it with `QEMU_BIN_PATH`;
`qemu-system-i386 -netdev help` should list `user`. Nothing else in the port
depends on this — real hardware and TAP-networked QEMU use the SDK's QEMU.

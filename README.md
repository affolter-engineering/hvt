# hvt

Too to do HTTP Verb Tampering. It probes HTTP methods against a target URL to uncover misconfigurations, bypasses and unintended method exposure.

If `hvt` doesn't suite your need, check those:

- Burp
- [TamperMAP](https://github.com/undefinedCody/TamperMAP)
- [httpmethods](https://github.com/ShutdownRepo/httpmethods)
- Burp

## What it does

Some web servers and proxies treat HTTP methods inconsistently. A path that returns `403` on `GET` might return `200` on `POST`, `PUT` or an obscure WebDAV method. `hvt` fires every method you choose against a target and surfaces anything worth investigating.

## Install

### Build from source

Requires Rust toolchain and a C linker (`gcc`).

```sh
git clone <repo>
cd hmt
cargo build --release
./target/release/hvt --help
```

### NixOS / nix-shell

```sh
nix-shell          # drops into a shell with cargo + gcc
cargo build --release
```

### Nix flake

```sh
nix build          # produces result/bin/hvt
nix run . -- -u https://example.com
nix develop        # dev shell
```

## Usage

```sh
hvt -u <URL> [OPTIONS]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url` | *(required)* | Target URL including scheme |
| `-t, --threads` | `5` | Concurrent request threads |
| `--all` | - | Test all 53 known methods (WebDAV, DeltaV, etc.) |
| `--safe` | - | Test only safe methods: GET, HEAD, OPTIONS |
| `-m, --methods` | - | Comma-separated custom method list |
| `-w, --wordlist` | - | File with one method per line (`#` for comments) |
| `-s, --show` | - | Show only these status codes (comma-separated) |
| `-x, --hide` | - | Hide these status codes (comma-separated) |
| `-H, --header` | - | Custom header, repeatable (`"Name: Value"`) |
| `-c, --cookie` | - | Cookie string (`"name=value; name2=value2"`) |
| `--proxy` | - | Proxy URL (`http://...` or `socks5://...`) |
| `-k, --insecure` | - | Accept invalid/self-signed TLS certificates |
| `-L, --follow-redirects` | - | Follow redirects (off by default to surface 3xx) |
| `-T, --timeout` | `10` | Per-request timeout in seconds |
| `-o, --output` | - | Save results to a text file |
| `-j, --json` | - | Export results to a JSON file |
| `-q, --quiet` | - | Suppress banner and info lines |

## Method sets

| Flag | Methods |
|------|---------|
| *(default)* | GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH |
| `--safe` | GET HEAD OPTIONS |
| `--all` | 53 methods - common + WebDAV (PROPFIND, MKCOL, COPY, MOVE, LOCK...), DeltaV (CHECKOUT, CHECKIN, MERGE...), and others (PURGE, SEARCH, SUBSCRIBE, REBIND...) |

## Examples

Basic scan with default 9 methods:

```sh
hvt -u https://example.com/admin
```

Full scan, 20 threads, hide 405:

```sh
hvt -u https://example.com --all -t 20 -x 405
```

Custom methods with auth header, save JSON:

```sh
hvt -u https://api.example.com/v1/users \
  -m GET,POST,PUT,DELETE,PATCH \
  -H "Authorization: Bearer <token>" \
  -j results.json
```

Through Burp Suite, ignore TLS errors:

```sh
hvt -u https://target.local/api -k --proxy http://127.0.0.1:8080
```

Wordlist mode, show only 2xx and 3xx:

```sh
hvt -u https://example.com -w methods.txt -s 200,201,301,302
```

Quiet mode for piping:

```sh
hvt -u https://example.com -q -j - | jq '.results[] | select(.status < 300)'
```

## Output

```sh
  Target  : https://example.com
  Methods : 9 (common)
  Threads : 5

 METHOD          STATUS    SIZE        TIME    INFO
──────────────────────────────────────────────────────────
 GET             200       1256 B      42ms    OK
 HEAD            200       0 B         38ms    OK
 POST            405       312 B       41ms    Method Not Allowed
 PUT             405       312 B       40ms    Method Not Allowed
 DELETE          405       312 B       39ms    Method Not Allowed
 CONNECT         400       0 B         38ms    Bad Request
 OPTIONS         200       0 B         38ms    OK  Allow: GET, HEAD, OPTIONS
 PATCH           405       312 B       39ms    Method Not Allowed

Summary
  Target  : https://example.com
  Tested  : 9
  Errors  : 0
  2xx     : GET [200], HEAD [200], OPTIONS [200]
```

Non-GET/HEAD methods that return 2xx or 3xx are flagged in the summary as potentially interesting.

## License

MIT

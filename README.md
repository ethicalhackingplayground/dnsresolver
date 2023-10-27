# dnsresolver

a very fast dns resolver

# Installation

```rust
cargo install --path .
```

# Usage

```bash
cat subs.txt | dnsresolver
```

If you need to resolve hosts with ports other than the standard 80 and 443, you can use the `--ports` flag.

```bash
cat subs.txt | dnsresolver -p 8080,8081
```

### Virtual Host Enumeration

If you wish to discover all the virtual hosts from a given subdomain list, you can use the `--vhost` flag.

make sure to increase the soft limit using `ulimit -n 10000` so we can handle more open files.

```bash
cat subs.txt | dnsresolver --vhost
```

# Demonstrations

[![asciicast](https://asciinema.org/a/g8lpcHqYeiYdljWxShrgX8naP.svg)](https://asciinema.org/a/g8lpcHqYeiYdljWxShrgX8naP)

[![asciicast](https://asciinema.org/a/GYBZM85QI6SbTiXz59Ncp1mT9.svg)](https://asciinema.org/a/GYBZM85QI6SbTiXz59Ncp1mT9)

[![asciicast](https://asciinema.org/a/VbhwK5GTEHeonVwh55Z6tsfHr.svg)](https://asciinema.org/a/VbhwK5GTEHeonVwh55Z6tsfHr)

## Feedback

If you have any feedback, please reach out to us at krypt0mux@gmail.com

## License

[MIT](https://choosealicense.com/licenses/mit/)

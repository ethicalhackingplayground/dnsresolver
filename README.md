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

# Demonstration

[![asciicast](https://asciinema.org/a/2DIsrRqlWNRDkjq9MOjgCHpTO.svg)](https://asciinema.org/a/2DIsrRqlWNRDkjq9MOjgCHpTO)

## Feedback

If you have any feedback, please reach out to us at krypt0mux@gmail.com

## License

[MIT](https://choosealicense.com/licenses/mit/)

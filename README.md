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

# Demonstration

[![asciicast](https://asciinema.org/a/2DIsrRqlWNRDkjq9MOjgCHpTO.svg)](https://asciinema.org/a/2DIsrRqlWNRDkjq9MOjgCHpTO)

## Feedback

If you have any feedback, please reach out to us at krypt0mux@gmail.com

## License

[MIT](https://choosealicense.com/licenses/mit/)

# dnsresolver

a very fast dns resolver

# Installation

Make sure you have rust installed, then run the following command to install dnsresolver.

```rust
git clone https://github.com/ethicalhackingplayground/dnsresolver ; cd dnsresolver ; cargo install --path .
```

# Usage

```bash
cat subs.txt | dnsresolver
```

If you need to resolve hosts with any ports, you can use the `--ports` flag.

```bash
cat subs.txt | dnsresolver -p 8080,8081
```

### Virtual Host Enumeration

#### Using Unresolved Domains

If you wish to discover all the virtual hosts from a given domain list, you can use the `--vhost` flag

followed by the `--vhost-file` flag.

This will attempt to access restricted pages by replace the host header with an unresolved domain from your domain list, the sift algorithm is implemented

to make sure the virtual host response is different to the actual response.

make sure to increase the soft limit using `ulimit -n 10000` so we can handle more open files.

```bash
cat subs.txt | dnsresolver --vhost --vhost-file domains.txt
```

#### Using Localhost

You can also use the `--vhost` flag with the `--check-localhost` flag to replace the host header with localhost, often times this allows you to access
restricted pages and can lead to some information disclosures and juicy admin panels.

```bash
cat subs.txt | dnsresolver --vhost --check-localhost
```

# Demonstrations

[![asciicast](https://asciinema.org/a/g8lpcHqYeiYdljWxShrgX8naP.svg)](https://asciinema.org/a/g8lpcHqYeiYdljWxShrgX8naP)

[![asciicast](https://asciinema.org/a/GYBZM85QI6SbTiXz59Ncp1mT9.svg)](https://asciinema.org/a/GYBZM85QI6SbTiXz59Ncp1mT9)

[![asciicast](https://asciinema.org/a/VbhwK5GTEHeonVwh55Z6tsfHr.svg)](https://asciinema.org/a/VbhwK5GTEHeonVwh55Z6tsfHr)

## Feedback

If you have any feedback, please reach out to us at krypt0mux@gmail.com or via twitter [https://twitter.com/z0idsec](https://twitter.com/z0idsec)

## License

[MIT](https://choosealicense.com/licenses/mit/)

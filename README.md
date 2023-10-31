# dnsresolver

<h1 align="center">
  <br>
<img src="https://github.com/ethicalhackingplayground/dnsresolver/blob/main/static/icon.png" width="200px" alt="DNS Resolver">
</h1>

<h4 align="center"><b>A Lightning-Fast DNS Resolver</b></h4>

---

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#usage)
  - [Resolving Hosts with Ports](#resolving-hosts-with-ports)
  - [Virtual Host Enumeration](#virtual-host-enumeration)
    - [Using Unresolved Domains](#using-unresolved-domains)
    - [Using Localhost](#using-localhost)
- [Demonstrations](#demonstrations)
- [Feedback](#feedback)
- [License](#license)

---

# Installation

Make sure you have rust installed, then run the following command to install dnsresolver.

```bash
git clone https://github.com/ethicalhackingplayground/dnsresolver ; cd dnsresolver ; cargo install --path .
```

---

# Usage

```bash
cat subs.txt | dnsresolver
```

If you need to resolve hosts with any ports, you can use the `--ports` flag.

```bash
cat subs.txt | dnsresolver -p 443,80,8080,8081
```

### Virtual Host Enumeration

#### Using Unresolved Domains

First step would be to get all the unresolved hosts from a given domain list using:

```bash
cat subs.txt | dnsresolver --show-unresolved | unresolved.txt
```

Then, to discover all the virtual hosts from a given domain list,

you can use the `--vhost` flag followed by the `--vhost-file` flag.

**dnsresolver** aims to bypass access restrictions on certain pages. It does so by substituting the host header with unresolved domains and using the sift algorithm. This ensures that the virtual host's response differs from the actual response. Remember to raise the soft limit using the command `ulimit -n 10000` to handle more files simultaneously.

```bash
cat subs.txt | dnsresolver --vhost --vhost-file unresolved.txt.txt
```

To validate a finding run this curl command:

```bash
curl -v -k thehost.com -H "Host: unresolved-domain.com"
```

#### Using Localhost

You can also use the `--vhost` flag with the `--check-localhost` flag to replace the host header with localhost, often times this allows you to access
restricted pages and can lead to some information disclosures and juicy admin panels.

```bash
cat subs.txt | dnsresolver --vhost --check-localhost
```

To validate a finding run this curl command:

```bash
curl -v -k thehost.com -H "Host: localhost"
```

# Demonstrations

[![asciicast](https://asciinema.org/a/g8lpcHqYeiYdljWxShrgX8naP.svg)](https://asciinema.org/a/g8lpcHqYeiYdljWxShrgX8naP)

[![asciicast](https://asciinema.org/a/GYBZM85QI6SbTiXz59Ncp1mT9.svg)](https://asciinema.org/a/GYBZM85QI6SbTiXz59Ncp1mT9)

[![asciicast](https://asciinema.org/a/VbhwK5GTEHeonVwh55Z6tsfHr.svg)](https://asciinema.org/a/VbhwK5GTEHeonVwh55Z6tsfHr)

## Feedback

If you have any feedback, please reach out to us at krypt0mux@gmail.com or via twitter [https://twitter.com/z0idsec](https://twitter.com/z0idsec)

## License

[MIT](https://choosealicense.com/licenses/mit/)

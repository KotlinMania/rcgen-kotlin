# rcgen-kotlin in Kotlin

[![GitHub link](https://img.shields.io/badge/GitHub-KotlinMania%2Frcgen--kotlin-blue.svg)](https://github.com/KotlinMania/rcgen-kotlin)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.kotlinmania/rcgen-kotlin)](https://central.sonatype.com/artifact/io.github.kotlinmania/rcgen-kotlin)
[![Build status](https://img.shields.io/github/actions/workflow/status/KotlinMania/rcgen-kotlin/ci.yml?branch=main)](https://github.com/KotlinMania/rcgen-kotlin/actions)

This is a Kotlin Multiplatform line-by-line transliteration port of [`rustls/rcgen`](https://github.com/rustls/rcgen).

**Original Project:** This port is based on [`rustls/rcgen`](https://github.com/rustls/rcgen). All design credit and project intent belong to the upstream authors; this repository is a faithful port to Kotlin Multiplatform with no behavioural changes intended.

### Porting status

This is an **in-progress port**. The goal is feature parity with the upstream Rust crate while providing a native Kotlin Multiplatform API. Every Kotlin file carries a `// port-lint: source <path>` header naming its upstream Rust counterpart so the AST-distance tool can track provenance.

---

## Upstream README — `rustls/rcgen`

> The text below is reproduced and lightly edited from [`https://github.com/rustls/rcgen`](https://github.com/rustls/rcgen). It is the upstream project's own description and remains under the upstream authors' authorship; links have been rewritten to absolute upstream URLs so they continue to resolve from this repository.

## rcgen

[![docs](https://docs.rs/rcgen/badge.svg)](https://docs.rs/rcgen)
[![crates.io](https://img.shields.io/crates/v/rcgen.svg)](https://crates.io/crates/rcgen)
[![dependency status](https://deps.rs/repo/github/est31/rcgen/status.svg)](https://deps.rs/repo/github/est31/rcgen)

Simple Rust library to generate X.509 certificates.

```Rust
use rcgen::{generate_simple_self_signed, CertifiedKey};
// Generate a certificate that's valid for "localhost" and "hello.world.example"
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names).unwrap();
println!("{}", cert.pem());
println!("{}", signing_key.serialize_pem());
```

## Trying it out with openssl

You can do this:

```
cargo run
openssl x509 -in certs/cert.pem -text -noout
```

For debugging, pasting the PEM formatted text
to [this](https://lapo.it/asn1js/) service is very useful.

## Trying it out with quinn

You can use rcgen together with the [quinn](https://github.com/quinn-rs/quinn) crate.
The whole set of commands is:
```
cargo run
cd ../quinn
cargo run --example server -- --cert ../rcgen/certs/cert.pem --key ../rcgen/certs/key.pem ./
cargo run --example client -- --ca ../rcgen/certs/cert.der https://localhost:4433/README.md

```

## MSRV

The MSRV policy is to strive for supporting 7-month old Rust versions.

### License
[license]: #license

This crate is distributed under the terms of both the MIT license
and the Apache License (Version 2.0), at your option.

See [LICENSE](https://github.com/rustls/rcgen/blob/HEAD/LICENSE) for details.

#### License of your contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

---

## About this Kotlin port

### Installation

```kotlin
dependencies {
    implementation("io.github.kotlinmania:rcgen-kotlin:0.1.0")
}
```

### Building

```bash
./gradlew build
./gradlew test
```

### Targets

- macOS arm64
- Linux x64
- Windows mingw-x64
- iOS arm64 / simulator-arm64 (Swift export + XCFramework)
- JS (browser + Node.js)
- Wasm-JS (browser + Node.js)
- Android (API 24+)

### Porting guidelines

See [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md) for translator discipline, port-lint header convention, and Rust → Kotlin idiom mapping.

### License

This Kotlin port is distributed under the same MIT license as the upstream [`rustls/rcgen`](https://github.com/rustls/rcgen). See [LICENSE](LICENSE) (and any sibling `LICENSE-*` / `NOTICE` files mirrored from upstream) for the full text.

Original work copyrighted by the rcgen authors.  
Kotlin port: Copyright (c) 2026 Sydney Renee and The Solace Project.

### Acknowledgments

Thanks to the [`rustls/rcgen`](https://github.com/rustls/rcgen) maintainers and contributors for the original Rust implementation. This port reproduces their work in Kotlin Multiplatform; bug reports about upstream design or behavior should go to the upstream repository.

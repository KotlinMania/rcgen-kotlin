# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 9/10 (90.0%)
- **Function parity:** 92/170 matched (target 282) — 54.1%
- **Class/type parity:** 37/56 matched (target 130) — 66.1%
- **Combined symbol parity:** 129/226 matched (target 412) — 57.1%
- **Average inline-code cosine:** 0.27 (function body across 8 matched files)
- **Average documentation cosine:** 0.46 (doc text across 8 matched files)
- **Cheat-zeroed Files:** 2
- **Critical Issues:** 9 files with <0.60 function similarity

## Priority 1: Fix Incomplete High-Dependency Files

No incomplete high-dependency files detected.

## Priority 2: Port Missing High-Value Files

Critical missing files (>10 dependencies):

No missing high-value files detected.

## Detailed Work Items

Every matched file is listed below with function and type symbol parity.

### 1. error

- **Target:** `rcgen.Error [PROVENANCE-FALLBACK]`
- **Similarity:** 0.00
- **Dependents:** 3
- **Priority Score:** 3030410.0
- **Functions:** 0/1 matched (target 5)
- **Missing functions:** `fmt`
- **Types:** 1/3 matched (target 27)
- **Missing types:** `Error`, `ExternalError`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/error.rs` vs expected `error.rs`
- **Proposed provenance header:** `// port-lint: source error.rs` (current: `// port-lint: source rcgen/src/error.rs`)
- **Lint issues:** 1

### 2. key_pair

- **Target:** `rcgen.KeyPair [PROVENANCE-FALLBACK]`
- **Similarity:** 0.38
- **Dependents:** 2
- **Priority Score:** 2073606.2
- **Functions:** 24/29 matched (target 33)
- **Missing functions:** `fmt`, `generate_rsa_inner`, `try_from`, `from`, `_err`
- **Types:** 5/7 matched (target 6)
- **Missing types:** `KeyPairKind`, `Error`
- **Tests:** 2/2 matched
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/key_pair.rs` vs expected `key_pair.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `tests:rcgen/src/key_pair.rs` vs expected `key_pair.rs`
- **Proposed provenance header:** `// port-lint: source key_pair.rs` (current: `// port-lint: source rcgen/src/key_pair.rs`)
- **Proposed provenance header:** `// port-lint: tests key_pair.rs` (current: `// port-lint: tests rcgen/src/key_pair.rs`)
- **Lint issues:** 2

### 3. oid

- **Target:** `rcgen.Oid [ZERO] [PROVENANCE-FALLBACK]`
- **Similarity:** 0.00
- **Dependents:** 1
- **Priority Score:** 1000010.0
- **Functions:** 0/0 matched (target 2)
- **Missing functions:** _none_
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/oid.rs` vs expected `oid.rs`
- **Proposed provenance header:** `// port-lint: source oid.rs` (current: `// port-lint: source rcgen/src/oid.rs`)
- **Lint issues:** 1

### 4. lib

- **Target:** `rcgen.Der [STUB] [PROVENANCE-FALLBACK]`
- **Similarity:** 0.00
- **Dependents:** 0
- **Priority Score:** 496310.0
- **Functions:** 11/49 matched (target 66)
- **Missing functions:** `deref`, `as_ref`, `key_usages`, `key`, `fmt`, `from_x509`, `from`, `ip_addr_from_octets`, `try_from_general`, `tag`, `get`, `remove`, `push`, `iter`, `from_name`, `to_u16`, `from_u16`, `derive`, `dt_strip_nanos`, `dt_to_generalized`, `write_dt_utc_or_generalized`, `write_distinguished_name`, `write_x509_extension`, `write_x509_authority_key_identifier`, `zeroize`, `from_slice`, `to_bytes`, `len`, `times`, `test_dt_utc_strip_nanos`, `test_dt_to_generalized`, `signature_algos_different`, `ipv4`, `ipv6`, `mismatch`, `none`, `too_many`, `with_ipv4`
- **Types:** 3/14 matched
- **Missing types:** `RcgenError`, `Target`, `SanType`, `OtherNameValue`, `DnValue`, `DistinguishedName`, `DistinguishedNameIterator`, `Item`, `KeyUsagePurpose`, `KeyIdMethod`, `SerialNumber`
- **Tests:** 0/10 matched
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/lib.rs` vs expected `lib.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/lib.rs` vs expected `lib.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/lib.rs` vs expected `lib.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/lib.rs` vs expected `lib.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `tests:rcgen/src/lib.rs` vs expected `lib.rs`
- **Proposed provenance header:** `// port-lint: source lib.rs` (current: `// port-lint: source rcgen/src/lib.rs`)
- **Proposed provenance header:** `// port-lint: source lib.rs` (current: `// port-lint: source rcgen/src/lib.rs`)
- **Proposed provenance header:** `// port-lint: source lib.rs` (current: `// port-lint: source rcgen/src/lib.rs`)
- **Proposed provenance header:** `// port-lint: source lib.rs` (current: `// port-lint: source rcgen/src/lib.rs`)
- **Proposed provenance header:** `// port-lint: tests lib.rs` (current: `// port-lint: tests rcgen/src/lib.rs`)
- **Lint issues:** 5

### 5. certificate

- **Target:** `rcgen.Certificate [PROVENANCE-FALLBACK]`
- **Similarity:** 0.44
- **Dependents:** 0
- **Priority Score:** 156005.6
- **Functions:** 34/48 matched (target 86)
- **Missing functions:** `default`, `from_ca_cert_der`, `as_ref`, `set_criticality`, `content`, `oid_components`, `from_x509`, `from_addr_prefix`, `from_v6_prefix`, `test_windows_line_endings`, `parse_other_name_alt_name`, `parse_ia5string_subject`, `converts_from_ip`, `load_ca_and_sign_cert`
- **Types:** 11/12 matched (target 58)
- **Missing types:** `Err`
- **Tests:** 5/10 matched
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/certificate.rs` vs expected `certificate.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `tests:rcgen/src/certificate.rs` vs expected `certificate.rs`
- **Proposed provenance header:** `// port-lint: source certificate.rs` (current: `// port-lint: source rcgen/src/certificate.rs`)
- **Proposed provenance header:** `// port-lint: tests certificate.rs` (current: `// port-lint: tests rcgen/src/certificate.rs`)
- **Lint issues:** 2

### 6. string

- **Target:** `rcgen.String [PROVENANCE-FALLBACK]`
- **Similarity:** 0.10
- **Dependents:** 0
- **Priority Score:** 102109.0
- **Functions:** 6/14 matched (target 51)
- **Missing functions:** `as_ref`, `fmt`, `eq`, `printable_string`, `ia5_string`, `teletext_string`, `bmp_string`, `universal_string`
- **Types:** 5/7 matched (target 6)
- **Missing types:** `Error`, `Err`
- **Tests:** 0/5 matched
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/string.rs` vs expected `string.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `tests:rcgen/src/string.rs` vs expected `string.rs`
- **Proposed provenance header:** `// port-lint: source string.rs` (current: `// port-lint: source rcgen/src/string.rs`)
- **Proposed provenance header:** `// port-lint: tests string.rs` (current: `// port-lint: tests rcgen/src/string.rs`)
- **Lint issues:** 2

### 7. sign_algo

- **Target:** `rcgen.SignAlgo [PROVENANCE-FALLBACK]`
- **Similarity:** 0.26
- **Dependents:** 0
- **Priority Score:** 61207.4
- **Functions:** 4/9 matched (target 14)
- **Missing functions:** `fmt`, `eq`, `hash`, `alg_ident_oid`, `write_params`
- **Types:** 2/3 matched (target 6)
- **Missing types:** `SignAlgo`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/sign_algo.rs` vs expected `sign_algo.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `tests:rcgen/src/sign_algo.rs` vs expected `sign_algo.rs`
- **Proposed provenance header:** `// port-lint: source sign_algo.rs` (current: `// port-lint: source rcgen/src/sign_algo.rs`)
- **Proposed provenance header:** `// port-lint: tests sign_algo.rs` (current: `// port-lint: tests rcgen/src/sign_algo.rs`)
- **Lint issues:** 2

### 8. csr

- **Target:** `rcgen.Csr [PROVENANCE-FALLBACK]`
- **Similarity:** 0.41
- **Dependents:** 0
- **Priority Score:** 31305.9
- **Functions:** 7/10 matched (target 14)
- **Missing functions:** `from`, `dont_write_sans_extension_if_no_sans_are_present`, `write_extension_request_if_ekus_are_present`
- **Types:** 3/3 matched (target 4)
- **Missing types:** _none_
- **Tests:** 0/2 matched
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/csr.rs` vs expected `csr.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `tests:rcgen/src/csr.rs` vs expected `csr.rs`
- **Proposed provenance header:** `// port-lint: source csr.rs` (current: `// port-lint: source rcgen/src/csr.rs`)
- **Proposed provenance header:** `// port-lint: tests csr.rs` (current: `// port-lint: tests rcgen/src/csr.rs`)
- **Lint issues:** 2

### 9. crl

- **Target:** `rcgen.Crl [PROVENANCE-FALLBACK]`
- **Similarity:** 0.56
- **Dependents:** 0
- **Priority Score:** 11404.4
- **Functions:** 6/7 matched (target 11)
- **Missing functions:** `from`
- **Types:** 7/7 matched (target 8)
- **Missing types:** _none_
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `rcgen/src/crl.rs` vs expected `crl.rs`
- **Provenance warning:** port-lint provenance header matched only after fallback normalization: `tests:rcgen/src/crl.rs` vs expected `crl.rs`
- **Proposed provenance header:** `// port-lint: source crl.rs` (current: `// port-lint: source rcgen/src/crl.rs`)
- **Proposed provenance header:** `// port-lint: tests crl.rs` (current: `// port-lint: tests rcgen/src/crl.rs`)
- **Lint issues:** 2

## Success Criteria

For each file to be considered "complete":
- **Similarity ≥ 0.85** (Excellent threshold)
- All public APIs ported
- All tests ported
- Documentation ported
- port-lint header present


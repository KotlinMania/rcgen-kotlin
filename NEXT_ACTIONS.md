# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 9/10 (90.0%)
- **Function parity:** 84/170 matched (target 215) — 49.4%
- **Class/type parity:** 37/56 matched (target 121) — 66.1%
- **Combined symbol parity:** 121/226 matched (target 336) — 53.5%
- **Average inline-code cosine:** 0.20 (function body across 9 matched files)
- **Average documentation cosine:** 0.45 (doc text across 9 matched files)
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

- **Target:** `rcgen.Error`
- **Similarity:** 0.00
- **Dependents:** 3
- **Priority Score:** 3030410.0
- **Functions:** 0/1 matched (target 5)
- **Missing functions:** `fmt`
- **Types:** 1/3 matched (target 27)
- **Missing types:** `Error`, `ExternalError`

### 2. key_pair

- **Target:** `rcgen.KeyPair [ZERO]`
- **Similarity:** 0.00
- **Dependents:** 2
- **Priority Score:** 2093610.0
- **Functions:** 22/29 matched (target 32)
- **Missing functions:** `fmt`, `generate_rsa_inner`, `try_from`, `from`, `_err`, `test_subject_public_key_parsing`, `test_algorithm`
- **Types:** 5/7 matched (target 6)
- **Missing types:** `KeyPairKind`, `Error`
- **Tests:** 0/2 matched
- **Lint issues:** 1

### 3. oid

- **Target:** `rcgen.Oid [ZERO]`
- **Similarity:** 0.00
- **Dependents:** 1
- **Priority Score:** 1000010.0
- **Functions:** 0/0 matched (target 2)
- **Missing functions:** _none_
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_

### 4. lib

- **Target:** `rcgen.Lib`
- **Similarity:** 0.11
- **Dependents:** 0
- **Priority Score:** 516308.9
- **Functions:** 9/49 matched (target 11)
- **Missing functions:** `deref`, `as_ref`, `key_usages`, `key`, `fmt`, `from_x509`, `write_der`, `from`, `ip_addr_from_octets`, `try_from_general`, `tag`, `get`, `remove`, `push`, `iter`, `from_name`, `next`, `to_u16`, `from_u16`, `derive`, `dt_strip_nanos`, `dt_to_generalized`, `write_dt_utc_or_generalized`, `write_distinguished_name`, `write_x509_extension`, `write_x509_authority_key_identifier`, `zeroize`, `from_slice`, `to_bytes`, `len`, `times`, `test_dt_utc_strip_nanos`, `test_dt_to_generalized`, `signature_algos_different`, `ipv4`, `ipv6`, `mismatch`, `none`, `too_many`, `with_ipv4`
- **Types:** 3/14 matched (target 5)
- **Missing types:** `RcgenError`, `Target`, `SanType`, `OtherNameValue`, `DnValue`, `DistinguishedName`, `DistinguishedNameIterator`, `Item`, `KeyUsagePurpose`, `KeyIdMethod`, `SerialNumber`
- **Tests:** 0/10 matched

### 5. certificate

- **Target:** `rcgen.Certificate`
- **Similarity:** 0.39
- **Dependents:** 0
- **Priority Score:** 196006.1
- **Functions:** 30/48 matched (target 79)
- **Missing functions:** `default`, `from_ca_cert_der`, `as_ref`, `set_criticality`, `content`, `oid_components`, `from_x509`, `from_addr_prefix`, `from_v6_prefix`, `test_with_key_usages_decipheronly_only`, `test_with_extended_key_usages_any`, `test_with_extended_key_usages_other`, `test_windows_line_endings`, `test_not_windows_line_endings`, `parse_other_name_alt_name`, `parse_ia5string_subject`, `converts_from_ip`, `load_ca_and_sign_cert`
- **Types:** 11/12 matched (target 58)
- **Missing types:** `Err`
- **Tests:** 1/10 matched

### 6. string

- **Target:** `rcgen.String`
- **Similarity:** 0.10
- **Dependents:** 0
- **Priority Score:** 102109.0
- **Functions:** 6/14 matched (target 49)
- **Missing functions:** `as_ref`, `fmt`, `eq`, `printable_string`, `ia5_string`, `teletext_string`, `bmp_string`, `universal_string`
- **Types:** 5/7 matched (target 6)
- **Missing types:** `Error`, `Err`
- **Tests:** 0/5 matched

### 7. sign_algo

- **Target:** `rcgen.SignAlgo`
- **Similarity:** 0.26
- **Dependents:** 0
- **Priority Score:** 61207.4
- **Functions:** 4/9 matched (target 14)
- **Missing functions:** `fmt`, `eq`, `hash`, `alg_ident_oid`, `write_params`
- **Types:** 2/3 matched (target 6)
- **Missing types:** `SignAlgo`

### 8. csr

- **Target:** `rcgen.Csr`
- **Similarity:** 0.41
- **Dependents:** 0
- **Priority Score:** 31305.9
- **Functions:** 7/10 matched (target 12)
- **Missing functions:** `from`, `dont_write_sans_extension_if_no_sans_are_present`, `write_extension_request_if_ekus_are_present`
- **Types:** 3/3 matched (target 4)
- **Missing types:** _none_
- **Tests:** 0/2 matched

### 9. crl

- **Target:** `rcgen.Crl`
- **Similarity:** 0.56
- **Dependents:** 0
- **Priority Score:** 11404.4
- **Functions:** 6/7 matched (target 11)
- **Missing functions:** `from`
- **Types:** 7/7 matched (target 8)
- **Missing types:** _none_

## Success Criteria

For each file to be considered "complete":
- **Similarity ≥ 0.85** (Excellent threshold)
- All public APIs ported
- All tests ported
- Documentation ported
- port-lint header present


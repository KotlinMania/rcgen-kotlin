# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 9/14 (64.3%)
- **Function parity:** 81/129 matched (target 216) — 62.8%
- **Class/type parity:** 34/42 matched (target 116) — 81.0%
- **Combined symbol parity:** 115/171 matched (target 332) — 67.3%
- **Average inline-code cosine:** 0.27 (function body across 8 matched files)
- **Average documentation cosine:** 0.46 (doc text across 8 matched files)
- **Cheat-zeroed Files:** 1
- **Critical Issues:** 9 files with <0.60 function similarity

## Priority 1: Fix Incomplete High-Dependency Files

No incomplete high-dependency files detected.

## Priority 2: Port Missing High-Value Files

Critical missing files (>10 dependencies):

No missing high-value files detected.

## Detailed Work Items

Every matched file is listed below with function and type symbol parity.

### 1. rcgen.error

- **Target:** `rcgen.Error`
- **Similarity:** 0.00
- **Dependents:** 4
- **Priority Score:** 4030410.0
- **Functions:** 0/1 matched (target 5)
- **Missing functions:** `fmt`
- **Types:** 1/3 matched (target 27)
- **Missing types:** `Error`, `ExternalError`

### 2. rcgen.key_pair

- **Target:** `rcgen.KeyPair`
- **Similarity:** 0.38
- **Dependents:** 2
- **Priority Score:** 2073606.2
- **Functions:** 24/29 matched (target 33)
- **Missing functions:** `fmt`, `generate_rsa_inner`, `try_from`, `from`, `_err`
- **Types:** 5/7 matched (target 6)
- **Missing types:** `KeyPairKind`, `Error`
- **Tests:** 2/2 matched

### 3. rcgen.oid

- **Target:** `rcgen.Oid [ZERO]`
- **Similarity:** 0.00
- **Dependents:** 1
- **Priority Score:** 1000010.0
- **Functions:** 0/0 matched (target 2)
- **Missing functions:** _none_
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_

### 4. rcgen.certificate

- **Target:** `rcgen.Certificate`
- **Similarity:** 0.44
- **Dependents:** 0
- **Priority Score:** 156005.6
- **Functions:** 34/48 matched (target 86)
- **Missing functions:** `default`, `from_ca_cert_der`, `as_ref`, `set_criticality`, `content`, `oid_components`, `from_x509`, `from_addr_prefix`, `from_v6_prefix`, `test_windows_line_endings`, `parse_other_name_alt_name`, `parse_ia5string_subject`, `converts_from_ip`, `load_ca_and_sign_cert`
- **Types:** 11/12 matched (target 58)
- **Missing types:** `Err`
- **Tests:** 5/10 matched

### 5. rcgen.string

- **Target:** `rcgen.String`
- **Similarity:** 0.10
- **Dependents:** 0
- **Priority Score:** 102109.0
- **Functions:** 6/14 matched (target 51)
- **Missing functions:** `as_ref`, `fmt`, `eq`, `printable_string`, `ia5_string`, `teletext_string`, `bmp_string`, `universal_string`
- **Types:** 5/7 matched (target 6)
- **Missing types:** `Error`, `Err`
- **Tests:** 0/5 matched

### 6. rcgen.sign_algo

- **Target:** `rcgen.SignAlgo`
- **Similarity:** 0.26
- **Dependents:** 0
- **Priority Score:** 61207.4
- **Functions:** 4/9 matched (target 14)
- **Missing functions:** `fmt`, `eq`, `hash`, `alg_ident_oid`, `write_params`
- **Types:** 2/3 matched (target 6)
- **Missing types:** `SignAlgo`

### 7. rcgen.csr

- **Target:** `rcgen.Csr`
- **Similarity:** 0.41
- **Dependents:** 0
- **Priority Score:** 31305.9
- **Functions:** 7/10 matched (target 14)
- **Missing functions:** `from`, `dont_write_sans_extension_if_no_sans_are_present`, `write_extension_request_if_ekus_are_present`
- **Types:** 3/3 matched (target 4)
- **Missing types:** _none_
- **Tests:** 0/2 matched

### 8. rcgen.crl

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

## Reexport / Wiring Modules

These files match `reexport_modules` patterns in `.ast_distance_config.json`. They are filtered out of
normal priority and missing-file ladders because they are wiring
modules, not direct logic ports. Consult them for call-site routing;
do not treat them as the next implementation target by default.

### Matched

| Source | Target | Path |
|--------|--------|------|
| `rcgen.lib` | `rcgen.Der` | `rcgen/src/lib` |


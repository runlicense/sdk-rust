# RunLicense SDK for Rust

License verification SDK for Rust crates using the [RunLicense](https://runlicense.com) system.

This SDK is for **native Rust crates** - if you're building a WebAssembly module,
use [sdk-webassembly-rust](https://github.com/runlicense/sdk-webassembly-rust) instead.

## Overview

The RunLicense Rust SDK lets crate developers add license verification to their libraries. It handles:

- **Ed25519 signature verification** - ensures the license file hasn't been tampered with
- **Status and expiry checks** - confirms the license is active and not expired
- **Namespaced license discovery** - multiple licensed crates can coexist in the same application
- **Phone-home validation** - server-side license verification with offline grace periods

## For Crate Developers

You're building a Rust crate and want to require a valid RunLicense license before your code runs.

### 1. Add the dependency

```toml
[dependencies]
runlicense-sdk-rust = "0.1"
```

### 2. Add your public key

Place your RunLicense public key at `keys/runlicense.key` in your crate root:

```
your-crate/
├── Cargo.toml
├── keys/
│   └── runlicense.key    # Your RunLicense Ed25519 public key
└── src/
    └── lib.rs
```

The key is a single line containing the base64-encoded Ed25519 public key. This is the same key shown
in your RunLicense dashboard. It gets embedded into your compiled crate at build time - it is never
read at runtime.

**Important:** Make sure `keys/runlicense.key` is not in your `.gitignore`, as Cargo respects
`.gitignore` when packaging crates for publishing. If the key file is excluded, downstream consumers
will get a build failure.

### 3. Verify the license

Choose a namespace for your crate. This is typically your organization and crate name
(e.g., `acme/image-processor`). Your end users will place their license file in a directory
matching this namespace.

```rust
use runlicense_sdk::{verify_license, LicenseError};

pub fn init() -> Result<(), LicenseError> {
    let license = verify_license!("acme/image-processor")?;

    println!("Licensed to customer: {}", license.customer_id);
    println!("Product: {}", license.product_id);

    // Check for specific features
    if let Some(features) = &license.allowed_features {
        println!("Features: {}", features);
    }

    Ok(())
}
```

`verify_license!` performs the full verification pipeline:

1. Discovers the license file at `runlicense/<namespace>/license.json`
2. Verifies the Ed25519 signature against the embedded public key
3. Checks that the license status is `"active"` and not expired
4. Phones home to the activation server for server-side validation
5. Caches the validation token on disk for offline grace periods

If the network is unavailable, the SDK falls back to a cached validation token if one exists and
hasn't expired. If there is no valid cached token, the verification fails.

#### With raw JSON

If you load the license JSON yourself (e.g., from a config file or API), use `verify_license_json!`:

```rust
use runlicense_sdk::{verify_license_json, LicenseError};

let json = std::fs::read_to_string("path/to/license.json").unwrap();
let license = verify_license_json!(&json)?;
```

This performs the same verification (including phone-home) but without filesystem-based token caching.

## For Application Developers

You're building a Rust application that depends on one or more licensed crates. Each licensed crate
expects its license file at a specific namespaced path.

### License file placement

Place each license file under a `runlicense/` directory, namespaced by the crate's registered
namespace:

```
my-application/
├── Cargo.toml
├── runlicense/
│   ├── acme/
│   │   └── image-processor/
│   │       └── license.json
│   └── widgets-inc/
│       └── chart-engine/
│           └── license.json
└── src/
    └── main.rs
```

Each licensed crate finds its own `license.json` independently - they don't interfere with each
other.

### Discovery order

The SDK searches for `runlicense/<namespace>/license.json` in these locations, using the first match:

1. **`RUNLICENSE_DIR` environment variable** - if set, looks for `$RUNLICENSE_DIR/<namespace>/license.json`
2. **Executable directory** - next to the compiled binary
3. **Current working directory** - where you run the application from

For deployed applications, it's common to place the `runlicense/` folder alongside the binary or set
`RUNLICENSE_DIR` to a fixed path.

### License file format

The `license.json` file is provided by RunLicense when you purchase or activate a license. It
contains a signed payload:

```json
{
  "payload": "{\"license_id\":\"lic_abc123\",\"product_id\":\"prod_xyz\",\"customer_id\":\"cust_456\",\"status\":\"active\",\"expiry_date\":\"2026-12-31T23:59:59Z\",\"allowed_features\":{\"pro\":true},\"usage_limit\":null,\"token_ttl\":3600,\"activation_url\":\"https://runlicense.com/activate/lic_abc123\"}",
  "signature": "base64-encoded-ed25519-signature"
}
```

You should not modify this file - any changes will cause signature verification to fail.

## API Reference

### Macros

| Macro | Returns | Description |
|---|---|---|
| `verify_license!("namespace")` | `Result<LicensePayload, LicenseError>` | Full verification: signature, status/expiry, phone-home |
| `verify_license_json!(&json)` | `Result<LicensePayload, LicenseError>` | Same verification from a JSON string (no token caching) |

### `LicensePayload`

Returned on successful verification:

| Field | Type | Description |
|---|---|---|
| `license_id` | `String` | Unique license identifier |
| `product_id` | `String` | Product this license is for |
| `customer_id` | `String` | Customer who owns the license |
| `status` | `String` | License status (must be `"active"`) |
| `expiry_date` | `Option<String>` | ISO 8601 expiry date, if set |
| `allowed_features` | `Option<serde_json::Value>` | Feature flags/limits, if configured |
| `usage_limit` | `Option<u64>` | Usage limit, if configured |
| `token_ttl` | `Option<u64>` | Validation token TTL in seconds |
| `activation_url` | `Option<String>` | Phone-home endpoint URL |

### `LicenseError`

All verification failures return a `LicenseError`:

| Variant | Meaning |
|---|---|
| `LicenseFileNotFound` | No license file found at expected paths |
| `LicenseFileUnreadable` | File exists but couldn't be read |
| `InvalidJson` | License file is not valid JSON |
| `InvalidPublicKey` | The embedded public key is malformed |
| `InvalidSignature` | The signature encoding is invalid |
| `SignatureMismatch` | Signature doesn't match - file may be tampered |
| `LicenseNotActive` | License status is not `"active"` |
| `LicenseExpired` | License has passed its expiry date |
| `NoActivationUrl` | License has no activation URL for phone-home |
| `PhoneHomeFailed` | Network request to activation server failed |
| `ServerRejected` | Activation server rejected the license |
| `InvalidValidationToken` | Server response was malformed |
| `ValidationTokenExpired` | Server token has expired |
| `ValidationTokenNonceMismatch` | Possible replay attack detected |
| `ValidationTokenLicenseMismatch` | Token doesn't match the license |

## Features

| Feature | Default | Description |
|---|---|---|
| `phone-home` | **yes** | Server-side validation via HTTP, token caching, offline grace periods |

> **Security warning for crate developers:** Do not disable the `phone-home` feature. Without it,
> the SDK can only verify licenses offline using the signature and expiry date. This means there is
> no server-side revocation - if you need to revoke a license, the SDK has no way to know. An end
> user could also roll back their system clock to bypass expiry checks. Phone-home is the primary
> enforcement mechanism and should always be enabled in production.

Offline-only mode is available for air-gapped environments where network access is not possible:

```toml
[dependencies]
runlicense-sdk-rust = { version = "0.1", default-features = false }
```

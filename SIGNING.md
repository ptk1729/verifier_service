# Report Signing and Verification

This document explains how to use the digital signing and verification features of the verifier service.

## Overview

The verifier service supports signing verification reports using ed25519 digital signatures. This ensures:

- **Authenticity**: Reports are cryptographically signed by a trusted source
- **Integrity**: Any tampering with the report will be detected
- **Non-repudiation**: The signer cannot deny creating the report

## Key Management

### Generating Key Pairs

Generate a new key pair for signing reports:

```bash
go run main.go -generate-keys
```

This creates:
- `private_key.bin`: Your private key (keep secure!)
- `public_key.bin`: Your public key (can be shared)
- `public_key.txt`: Public key in base64 format

### Private Key Storage

You can store your private key in two ways:

1. **File-based**: Use the `-private-key` flag
2. **Environment variable**: Set `VERIFIER_PRIVATE_KEY` with base64-encoded key

To encode your private key for environment variable:
```bash
export VERIFIER_PRIVATE_KEY=$(base64 -w 0 private_key.bin)
```

## Signing Reports

### Basic Signing

Sign a verification report using a private key file:

```bash
go run main.go -sign -private-key=private_key.bin https://github.com/user/repo
```

### Environment Variable Signing

Sign using a private key from environment variable:

```bash
export VERIFIER_PRIVATE_KEY="your_base64_encoded_private_key"
go run main.go -sign https://github.com/user/repo
```

### Output

Signed reports are saved with the SHA256 hash in the filename:
```
/tmp/report_a1b2c3d4e5f6...json
```

The signed report contains:
- Original report data
- SHA256 hash of the report
- Base64-encoded signature

## Verifying Reports

### Basic Verification

Verify a signed report using a public key:

```bash
go run main.go -verify -public-key=public_key.bin report_file.json
```

### Verification with Report Display

Verify and display the report content:

```bash
go run main.go -verify -public-key=public_key.bin -print-report report_file.json
```

## Complete Example

Run the example script to see the full workflow:

```bash
chmod +x examples/signing_example.sh
./examples/signing_example.sh
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Security Verification
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Run verification with signing
        env:
          VERIFIER_PRIVATE_KEY: ${{ secrets.VERIFIER_PRIVATE_KEY }}
        run: |
          go run main.go -sign -output-dir=./reports https://github.com/${{ github.repository }}
      
      - name: Upload signed report
        uses: actions/upload-artifact@v3
        with:
          name: verification-report
          path: reports/
```

### GitLab CI Example

```yaml
verify:
  image: golang:1.21
  script:
    - go run main.go -sign -output-dir=./reports $CI_PROJECT_URL
  artifacts:
    paths:
      - reports/
  variables:
    VERIFIER_PRIVATE_KEY: $VERIFIER_PRIVATE_KEY
```

## Security Best Practices

1. **Private Key Security**:
   - Never commit private keys to version control
   - Use environment variables or secure key management systems
   - Rotate keys periodically

2. **Public Key Distribution**:
   - Share public keys securely with verification systems
   - Consider using a public key infrastructure (PKI)

3. **Report Storage**:
   - Store signed reports in secure, tamper-evident storage
   - Consider using blockchain or similar immutable storage

4. **Verification**:
   - Always verify reports before processing
   - Implement automated verification in consuming systems

## API Integration

For programmatic use, the signing functions are available in the `report` package:

```go
import "github.com/ptk1729/verifier_service/report"

// Generate a key pair
priv, pub, err := report.GenerateKeyPair()

// Sign a report
signedReport, err := report.SignReport(myReport, priv)

// Verify a report
err := report.VerifySignedReport(signedReport, pub)
```

## Troubleshooting

### Common Issues

1. **"environment variable not set"**: Set `VERIFIER_PRIVATE_KEY` or use `-private-key` flag
2. **"signature verification failed"**: Check that you're using the correct public key
3. **"invalid private key size"**: Ensure the key is properly base64 encoded

### Key Formats

- Private keys: 32 bytes (256 bits) for ed25519
- Public keys: 32 bytes (256 bits) for ed25519
- Environment variable: Base64 encoded private key

## Cryptographic Details

- **Algorithm**: ed25519 (Edwards-curve Digital Signature Algorithm)
- **Hash Function**: SHA-256
- **Key Size**: 256 bits
- **Signature Size**: 64 bytes
- **Encoding**: Base64 for signatures, hex for hashes 
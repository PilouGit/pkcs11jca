# PKCS#11 JNA Provider

Java Native Access (JNA) mapping for PKCS#11 Cryptoki standard with support for SoftHSM vendor extensions including Post-Quantum Cryptography (PQC) hybrid schemes.

## Overview

This library provides a complete Java interface to PKCS#11 cryptographic tokens using JNA. It includes:

- Full PKCS#11 v3.2 specification support
- JNA-based native library bindings
- SoftHSM vendor-specific extensions for PQC hybrid schemes
- Type-safe structures and constants
- Helper methods for common operations

## Features

### PKCS#11 Standard Functions

The library provides access to all standard PKCS#11 functions:

- **General Functions**: Initialize, Finalize, GetInfo
- **Slot & Token Management**: GetSlotList, GetTokenInfo, InitToken
- **Session Management**: OpenSession, CloseSession, Login, Logout
- **Object Management**: CreateObject, FindObjects, GetAttributeValue
- **Cryptographic Operations**:
  - Encryption/Decryption
  - Signing/Verification
  - Digest/Hashing
  - Key Generation
  - Key Derivation
- **Random Number Generation**

### SoftHSM Vendor Extensions

Support for Post-Quantum Cryptography hybrid schemes:

#### Hybrid KEM Mechanisms
- **ML-KEM-768 + ECDH P-256** (`CKM_VENDOR_MLKEM768_ECDH_P256`)
- **ML-KEM-1024 + ECDH P-384** (`CKM_VENDOR_MLKEM1024_ECDH_P384`)
- **ML-KEM-768 + X25519** (`CKM_VENDOR_MLKEM768_X25519`)

#### Hybrid Signature Mechanisms
- **ML-DSA-65 + ECDSA P-256** (`CKM_VENDOR_MLDSA65_ECDSA_P256`)
- **ML-DSA-87 + ECDSA P-384** (`CKM_VENDOR_MLDSA87_ECDSA_P384`)

#### Hybrid Key Types
- `CKK_VENDOR_HYBRID_KEM` - Hybrid KEM key pairs
- `CKK_VENDOR_HYBRID_SIGNATURE` - Hybrid signature key pairs

#### Hybrid Attributes
- `CKA_VENDOR_PQC_PUBLIC_KEY` - PQC public key component
- `CKA_VENDOR_PQC_PRIVATE_KEY` - PQC private key component
- `CKA_VENDOR_CLASSICAL_PUBLIC_KEY` - Classical public key component
- `CKA_VENDOR_CLASSICAL_PRIVATE_KEY` - Classical private key component
- `CKA_VENDOR_HYBRID_MECHANISM` - Hybrid mechanism identifier

## Requirements

- Java 11 or higher
- JNA 5.14.0 or higher
- A PKCS#11 compliant library (e.g., SoftHSMv2)

## Installation

### Maven

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.pilougit</groupId>
    <artifactId>pkcs11-provider</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### Build from Source

```bash
cd /home/pilou/myprojects/postquantum/pkcs11provider
mvn clean install
```

## Usage

### Basic Example

```java
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

// Load the PKCS#11 library
PKCS11Library pkcs11 = PKCS11Library.getInstance("/usr/lib/softhsm/libsofthsm2.so");

        // Initialize
        NativeLong rv = pkcs11.C_Initialize(null);
if(!rv.

        equals(PKCS11Types.CKR_OK)){
        throw new

        RuntimeException("Failed to initialize");
}

        // Get slot list
        NativeLongByReference slotCount = new NativeLongByReference();
pkcs11.

        C_GetSlotList(PKCS11Types.CK_TRUE, null,slotCount);

        NativeLong[] slots = new NativeLong[slotCount.getValue().intValue()];
pkcs11.

        C_GetSlotList(PKCS11Types.CK_TRUE, slots, slotCount);

        // Open session
        NativeLongByReference session = new NativeLongByReference();
        rv =pkcs11.

        C_OpenSession(
                slots[0],
                PKCS11Types.CKF_SERIAL_SESSION.or(PKCS11Types.CKF_RW_SESSION),
    null,
            null,
        session
);

        // Login
        byte[] pin = "1234".getBytes();
        rv =pkcs11.

        C_Login(session.getValue(),PKCS11Types.CKU_USER,pin,new

        NativeLong(pin.length));

// ... perform cryptographic operations ...

// Logout and cleanup
        pkcs11.

        C_Logout(session.getValue());
        pkcs11.

        C_CloseSession(session.getValue());
        pkcs11.

        C_Finalize(null);
```

### Using Hybrid KEM

```java
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types;
import io.github.pilougit.security.pkcs11.jca.util.jna.VendorDefines;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

// Generate hybrid KEM key pair
PKCS11Structures.CK_MECHANISM mechanism = new PKCS11Structures.CK_MECHANISM(
        VendorDefines.CKM_VENDOR_MLKEM768_ECDH_P256
);

        PKCS11Structures.CK_ATTRIBUTE[] publicTemplate = new PKCS11Structures.CK_ATTRIBUTE[]{
                new PKCS11Structures.CK_ATTRIBUTE(PKCS11Types.CKA_TOKEN, /* ... */, /* ... */),
                new PKCS11Structures.CK_ATTRIBUTE(PKCS11Types.CKA_ENCRYPT, /* ... */, /* ... */)
        };

        PKCS11Structures.CK_ATTRIBUTE[] privateTemplate = new PKCS11Structures.CK_ATTRIBUTE[]{
                new PKCS11Structures.CK_ATTRIBUTE(PKCS11Types.CKA_TOKEN, /* ... */, /* ... */),
                new PKCS11Structures.CK_ATTRIBUTE(PKCS11Types.CKA_DECRYPT, /* ... */, /* ... */)
        };

        NativeLongByReference publicKey = new NativeLongByReference();
        NativeLongByReference privateKey = new NativeLongByReference();

        NativeLong rv = pkcs11.C_GenerateKeyPair(
                session.getValue(),
                mechanism,
                publicTemplate, new NativeLong(publicTemplate.length),
                privateTemplate, new NativeLong(privateTemplate.length),
                publicKey,
                privateKey
        );

// Check if it's a hybrid mechanism
if(VendorDefines.

        isHybridKEMMechanism(mechanism.mechanism)){
        System.out.

        println("Generated hybrid KEM key pair: "+
                VendorDefines.getHybridMechanismName(mechanism.mechanism));
        }
```

### Using Hybrid Signatures

```java
// Generate hybrid signature key pair
PKCS11Structures.CK_MECHANISM sigMechanism = new PKCS11Structures.CK_MECHANISM(
    VendorDefines.CKM_VENDOR_MLDSA65_ECDSA_P256
);

// ... similar to KEM example ...

// Sign data
PKCS11Structures.CK_MECHANISM signMechanism = new PKCS11Structures.CK_MECHANISM(
    VendorDefines.CKM_VENDOR_MLDSA65_ECDSA_P256
);

rv = pkcs11.C_SignInit(session.getValue(), signMechanism, privateKey.getValue());

byte[] data = "Hello, hybrid signatures!".getBytes();
NativeLongByReference signatureLen = new NativeLongByReference();

// Get signature length
pkcs11.C_Sign(session.getValue(), data, new NativeLong(data.length), null, signatureLen);

// Get signature
byte[] signature = new byte[signatureLen.getValue().intValue()];
pkcs11.C_Sign(session.getValue(), data, new NativeLong(data.length), signature, signatureLen);
```

## Project Structure

```
pkcs11provider/
├── pom.xml
├── README.md
└── src/
    ├── main/
    │   └── java/
    │       └── io/
    │           └── github/
    │               └── pilougit/
    │                   └── security/
    │                       └── pkcs11/
    │                           └── jna/
    │                               ├── PKCS11Library.java       # Main JNA interface
    │                               ├── PKCS11Types.java         # Constants and types
    │                               ├── PKCS11Structures.java    # Data structures
    │                               ├── PKCS11Mechanisms.java    # Mechanism constants
    │                               └── VendorDefines.java       # SoftHSM extensions
    └── test/
        └── java/
            └── io/
                └── github/
                    └── pilougit/
                        └── security/
                            └── pkcs11/
                                └── jna/
```

## API Reference

### Main Classes

#### `PKCS11Library`
Main interface for PKCS#11 functions. Load with:
```java
PKCS11Library pkcs11 = PKCS11Library.getInstance("/path/to/pkcs11.so");
```

#### `PKCS11Types`
Contains all PKCS#11 constants:
- Return values (CKR_*)
- Object classes (CKO_*)
- Key types (CKK_*)
- Attribute types (CKA_*)
- User types (CKU_*)
- Flags (CKF_*)

#### `PKCS11Structures`
JNA structures for PKCS#11:
- `CK_VERSION`
- `CK_INFO`
- `CK_SLOT_INFO`
- `CK_TOKEN_INFO`
- `CK_SESSION_INFO`
- `CK_ATTRIBUTE`
- `CK_MECHANISM`
- `CK_MECHANISM_INFO`
- And more...

#### `PKCS11Mechanisms`
Mechanism type constants including:
- RSA, DSA, ECDSA mechanisms
- AES, DES encryption
- SHA-1, SHA-256, SHA-512 hashing
- HMAC mechanisms
- Post-Quantum mechanisms (ML-KEM, ML-DSA, SLH-DSA)

#### `VendorDefines`
SoftHSM vendor-specific extensions:
- Hybrid mechanism constants
- Hybrid key types and attributes
- Helper methods for hybrid mechanisms
- `CK_HYBRID_MECHANISM_INFO` structure

## Testing with SoftHSM

### Setup SoftHSM

```bash
# Initialize token
softhsm2-util --init-token --slot 0 --label "Test Token" --so-pin 1234 --pin 1234

# List tokens
softhsm2-util --show-slots
```

### Run Tests

```bash
mvn test -Dpkcs11.library=/usr/lib/softhsm/libsofthsm2.so
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is open source. See LICENSE file for details.

## Related Projects

- [SoftHSMv2](https://github.com/opendnssec/SoftHSMv2) - Software implementation of PKCS#11
- [JNA](https://github.com/java-native-access/jna) - Java Native Access
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/) - Official PKCS#11 v3.2 specification

## References

- PKCS#11 v3.2 Specification
- SoftHSMv2 Documentation
- NIST Post-Quantum Cryptography Standards
  - ML-KEM (FIPS 203)
  - ML-DSA (FIPS 204)
  - SLH-DSA (FIPS 205)

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review PKCS#11 specification
# pkcs11jca

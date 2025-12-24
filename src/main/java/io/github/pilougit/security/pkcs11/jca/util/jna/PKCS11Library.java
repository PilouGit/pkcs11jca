package io.github.pilougit.security.pkcs11.jca.util.jna;

import com.sun.jna.*;
import com.sun.jna.ptr.NativeLongByReference;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * JNA interface for PKCS#11 Cryptoki library.
 * This interface declares all the standard PKCS#11 functions as defined in the specification.
 *
 * Usage example:
 * <pre>
 * PKCS11Library pkcs11 = PKCS11Library.getInstance("/path/to/pkcs11/library.so");
 * NativeLongByReference rv = new NativeLongByReference();
 * pkcs11.C_Initialize(null);
 * </pre>
 */
public interface PKCS11Library extends Library {

    /**
     * Load a PKCS#11 library from the given path.
     *
     * @param libraryPath Path to the PKCS#11 shared library (.so, .dll, .dylib)
     * @return An instance of the PKCS11Library interface
     */
    static PKCS11Library getInstance(String libraryPath) {
        Map<String, Object> options = new HashMap<>();
        options.put(Library.OPTION_FUNCTION_MAPPER, new FunctionMapper() {
            @Override
            public String getFunctionName(NativeLibrary library, Method method) {
                // Use standard PKCS#11 function names
                return method.getName();
            }
        });
        return Native.load(libraryPath, PKCS11Library.class, options);
    }
    static PKCS11Library getInstance(Path libraryPath) {
        return getInstance(libraryPath.toAbsolutePath().toString());
    }

    // ========================================================================
    // General purpose functions
    // ========================================================================

    /**
     * C_Initialize initializes the Cryptoki library.
     *
     * @param pInitArgs initialization arguments or NULL
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Initialize(Pointer pInitArgs);

    /**
     * C_Finalize indicates that an application is done with the Cryptoki library.
     *
     * @param pReserved reserved for future use, should be NULL
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Finalize(Pointer pReserved);

    /**
     * C_GetInfo returns general information about Cryptoki.
     *
     * @param pInfo pointer to CK_INFO structure
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetInfo(PKCS11Structures.CK_INFO pInfo);

    /**
     * C_GetFunctionList returns a pointer to the Cryptoki library's function list.
     *
     * @param ppFunctionList pointer to function list pointer
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetFunctionList(Pointer ppFunctionList);

    // ========================================================================
    // Slot and token management functions
    // ========================================================================

    /**
     * C_GetSlotList obtains a list of slots in the system.
     *
     * @param tokenPresent only slots with tokens?
     * @param pSlotList array of slot IDs (can be NULL to get count)
     * @param pulCount pointer to number of slots
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetSlotList(byte tokenPresent, NativeLong[] pSlotList, NativeLongByReference pulCount);

    /**
     * C_GetSlotInfo obtains information about a particular slot.
     *
     * @param slotID the ID of the slot
     * @param pInfo pointer to CK_SLOT_INFO structure
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetSlotInfo(NativeLong slotID, PKCS11Structures.CK_SLOT_INFO pInfo);

    /**
     * C_GetTokenInfo obtains information about a particular token.
     *
     * @param slotID the ID of the token's slot
     * @param pInfo pointer to CK_TOKEN_INFO structure
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetTokenInfo(NativeLong slotID, PKCS11Structures.CK_TOKEN_INFO pInfo);

    /**
     * C_GetMechanismList obtains a list of mechanism types supported by a token.
     *
     * @param slotID the ID of the token's slot
     * @param pMechanismList array of mechanism types (can be NULL to get count)
     * @param pulCount pointer to number of mechanisms
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetMechanismList(NativeLong slotID, NativeLong[] pMechanismList, NativeLongByReference pulCount);

    /**
     * C_GetMechanismInfo obtains information about a particular mechanism.
     *
     * @param slotID the ID of the token's slot
     * @param type the type of mechanism
     * @param pInfo pointer to CK_MECHANISM_INFO structure
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetMechanismInfo(NativeLong slotID, NativeLong type, PKCS11Structures.CK_MECHANISM_INFO pInfo);

    /**
     * C_InitToken initializes a token.
     *
     * @param slotID the ID of the token's slot
     * @param pPin the SO's initial PIN
     * @param ulPinLen length in bytes of the PIN
     * @param pLabel 32-byte token label (blank padded)
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_InitToken(NativeLong slotID, byte[] pPin, NativeLong ulPinLen, byte[] pLabel);

    /**
     * C_InitPIN initializes the normal user's PIN.
     *
     * @param hSession the session's handle
     * @param pPin the normal user's PIN
     * @param ulPinLen length in bytes of the PIN
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_InitPIN(NativeLong hSession, byte[] pPin, NativeLong ulPinLen);

    /**
     * C_SetPIN modifies the PIN of the user who is logged in.
     *
     * @param hSession the session's handle
     * @param pOldPin the old PIN
     * @param ulOldLen length of the old PIN
     * @param pNewPin the new PIN
     * @param ulNewLen length of the new PIN
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_SetPIN(NativeLong hSession, byte[] pOldPin, NativeLong ulOldLen, byte[] pNewPin, NativeLong ulNewLen);

    // ========================================================================
    // Session management functions
    // ========================================================================

    /**
     * C_OpenSession opens a session between an application and a token.
     *
     * @param slotID the slot's ID
     * @param flags session flags
     * @param pApplication application callback parameter
     * @param Notify notification callback
     * @param phSession pointer to session handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_OpenSession(NativeLong slotID, NativeLong flags, Pointer pApplication, Pointer Notify, NativeLongByReference phSession);

    /**
     * C_CloseSession closes a session.
     *
     * @param hSession the session's handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_CloseSession(NativeLong hSession);

    /**
     * C_CloseAllSessions closes all sessions with a token.
     *
     * @param slotID the token's slot ID
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_CloseAllSessions(NativeLong slotID);

    /**
     * C_GetSessionInfo obtains information about the session.
     *
     * @param hSession the session's handle
     * @param pInfo pointer to CK_SESSION_INFO structure
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetSessionInfo(NativeLong hSession, PKCS11Structures.CK_SESSION_INFO pInfo);

    /**
     * C_Login logs a user into a token.
     *
     * @param hSession the session's handle
     * @param userType the user type (CKU_SO or CKU_USER)
     * @param pPin the user's PIN
     * @param ulPinLen the length of the PIN
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Login(NativeLong hSession, NativeLong userType, byte[] pPin, NativeLong ulPinLen);

    /**
     * C_Logout logs a user out from a token.
     *
     * @param hSession the session's handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Logout(NativeLong hSession);

    // ========================================================================
    // Object management functions
    // ========================================================================

    /**
     * C_CreateObject creates a new object.
     *
     * @param hSession the session's handle
     * @param pTemplate the object's template
     * @param ulCount attributes in template
     * @param phObject pointer to new object's handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_CreateObject(NativeLong hSession, PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulCount, NativeLongByReference phObject);

    /**
     * C_CopyObject copies an object, creating a new object for the copy.
     *
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pTemplate template for new object
     * @param ulCount attributes in template
     * @param phNewObject pointer to new object's handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_CopyObject(NativeLong hSession, NativeLong hObject, PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulCount, NativeLongByReference phNewObject);

    /**
     * C_DestroyObject destroys an object.
     *
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DestroyObject(NativeLong hSession, NativeLong hObject);

    /**
     * C_GetAttributeValue obtains the value of one or more object attributes.
     *
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pTemplate template with attribute types to get
     * @param ulCount number of attributes in template
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GetAttributeValue(NativeLong hSession, NativeLong hObject, PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulCount);

    /**
     * C_SetAttributeValue modifies the value of one or more object attributes.
     *
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pTemplate template with attributes to set
     * @param ulCount number of attributes in template
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_SetAttributeValue(NativeLong hSession, NativeLong hObject, PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulCount);

    /**
     * C_FindObjectsInit initializes a search for token and session objects.
     *
     * @param hSession the session's handle
     * @param pTemplate attribute values to match
     * @param ulCount number of attributes in search template
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_FindObjectsInit(NativeLong hSession, PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulCount);

    /**
     * C_FindObjects continues a search for token and session objects.
     *
     * @param hSession the session's handle
     * @param phObject array for returned object handles
     * @param ulMaxObjectCount max number of objects to return
     * @param pulObjectCount pointer to number of objects returned
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_FindObjects(NativeLong hSession, NativeLong[] phObject, NativeLong ulMaxObjectCount, NativeLongByReference pulObjectCount);

    /**
     * C_FindObjectsFinal finishes a search for token and session objects.
     *
     * @param hSession the session's handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_FindObjectsFinal(NativeLong hSession);

    // ========================================================================
    // Encryption and decryption functions
    // ========================================================================

    /**
     * C_EncryptInit initializes an encryption operation.
     *
     * @param hSession the session's handle
     * @param pMechanism the encryption mechanism
     * @param hKey handle of encryption key
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_EncryptInit(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hKey);

    /**
     * C_Encrypt encrypts single-part data.
     *
     * @param hSession the session's handle
     * @param pData the plaintext data
     * @param ulDataLen bytes of plaintext
     * @param pEncryptedData buffer for ciphertext (can be NULL)
     * @param pulEncryptedDataLen pointer to ciphertext length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Encrypt(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pEncryptedData, NativeLongByReference pulEncryptedDataLen);

    /**
     * C_EncryptUpdate continues a multiple-part encryption.
     *
     * @param hSession the session's handle
     * @param pPart the plaintext data
     * @param ulPartLen plaintext data length
     * @param pEncryptedPart buffer for ciphertext (can be NULL)
     * @param pulEncryptedPartLen pointer to ciphertext length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_EncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);

    /**
     * C_EncryptFinal finishes a multiple-part encryption.
     *
     * @param hSession the session's handle
     * @param pLastEncryptedPart buffer for last ciphertext (can be NULL)
     * @param pulLastEncryptedPartLen pointer to last ciphertext length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_EncryptFinal(NativeLong hSession, byte[] pLastEncryptedPart, NativeLongByReference pulLastEncryptedPartLen);

    /**
     * C_DecryptInit initializes a decryption operation.
     *
     * @param hSession the session's handle
     * @param pMechanism the decryption mechanism
     * @param hKey handle of decryption key
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DecryptInit(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hKey);

    /**
     * C_Decrypt decrypts encrypted data in a single part.
     *
     * @param hSession the session's handle
     * @param pEncryptedData the ciphertext
     * @param ulEncryptedDataLen ciphertext length
     * @param pData buffer for plaintext (can be NULL)
     * @param pulDataLen pointer to plaintext length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Decrypt(NativeLong hSession, byte[] pEncryptedData, NativeLong ulEncryptedDataLen, byte[] pData, NativeLongByReference pulDataLen);

    /**
     * C_DecryptUpdate continues a multiple-part decryption.
     *
     * @param hSession the session's handle
     * @param pEncryptedPart the ciphertext
     * @param ulEncryptedPartLen ciphertext length
     * @param pPart buffer for plaintext (can be NULL)
     * @param pulPartLen pointer to plaintext length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DecryptUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);

    /**
     * C_DecryptFinal finishes a multiple-part decryption.
     *
     * @param hSession the session's handle
     * @param pLastPart buffer for plaintext (can be NULL)
     * @param pulLastPartLen pointer to plaintext length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DecryptFinal(NativeLong hSession, byte[] pLastPart, NativeLongByReference pulLastPartLen);

    // ========================================================================
    // Message digesting functions
    // ========================================================================

    /**
     * C_DigestInit initializes a message-digesting operation.
     *
     * @param hSession the session's handle
     * @param pMechanism the digesting mechanism
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DigestInit(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism);

    /**
     * C_Digest digests data in a single part.
     *
     * @param hSession the session's handle
     * @param pData data to be digested
     * @param ulDataLen bytes of data to digest
     * @param pDigest buffer for digest (can be NULL)
     * @param pulDigestLen pointer to digest length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Digest(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pDigest, NativeLongByReference pulDigestLen);

    /**
     * C_DigestUpdate continues a multiple-part message-digesting.
     *
     * @param hSession the session's handle
     * @param pPart data to be digested
     * @param ulPartLen bytes of data to be digested
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DigestUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);

    /**
     * C_DigestFinal finishes a multiple-part message-digesting operation.
     *
     * @param hSession the session's handle
     * @param pDigest buffer for digest (can be NULL)
     * @param pulDigestLen pointer to digest length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DigestFinal(NativeLong hSession, byte[] pDigest, NativeLongByReference pulDigestLen);

    // ========================================================================
    // Signing and MACing functions
    // ========================================================================

    /**
     * C_SignInit initializes a signature operation.
     *
     * @param hSession the session's handle
     * @param pMechanism the signature mechanism
     * @param hKey handle of signature key
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_SignInit(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hKey);

    /**
     * C_Sign signs data in a single part.
     *
     * @param hSession the session's handle
     * @param pData the data to sign
     * @param ulDataLen count of bytes to sign
     * @param pSignature buffer for signature (can be NULL)
     * @param pulSignatureLen pointer to signature length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Sign(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);

    /**
     * C_SignUpdate continues a multiple-part signature operation.
     *
     * @param hSession the session's handle
     * @param pPart the data to sign
     * @param ulPartLen count of bytes to sign
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_SignUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);

    /**
     * C_SignFinal finishes a multiple-part signature operation.
     *
     * @param hSession the session's handle
     * @param pSignature buffer for signature (can be NULL)
     * @param pulSignatureLen pointer to signature length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_SignFinal(NativeLong hSession, byte[] pSignature, NativeLongByReference pulSignatureLen);

    // ========================================================================
    // Functions for verifying signatures and MACs
    // ========================================================================

    /**
     * C_VerifyInit initializes a verification operation.
     *
     * @param hSession the session's handle
     * @param pMechanism the verification mechanism
     * @param hKey handle of verification key
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_VerifyInit(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hKey);

    /**
     * C_Verify verifies a signature in a single-part operation.
     *
     * @param hSession the session's handle
     * @param pData signed data
     * @param ulDataLen length of signed data
     * @param pSignature signature
     * @param ulSignatureLen signature length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_Verify(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLong ulSignatureLen);

    /**
     * C_VerifyUpdate continues a multiple-part verification operation.
     *
     * @param hSession the session's handle
     * @param pPart signed data
     * @param ulPartLen length of signed data
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_VerifyUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);

    /**
     * C_VerifyFinal finishes a multiple-part verification operation.
     *
     * @param hSession the session's handle
     * @param pSignature signature to verify
     * @param ulSignatureLen signature length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_VerifyFinal(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen);

    // ========================================================================
    // Key management functions
    // ========================================================================

    /**
     * C_GenerateKey generates a secret key.
     *
     * @param hSession the session's handle
     * @param pMechanism key generation mechanism
     * @param pTemplate template for the new key
     * @param ulCount number of attributes in template
     * @param phKey pointer to handle for new key
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GenerateKey(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulCount, NativeLongByReference phKey);

    /**
     * C_GenerateKeyPair generates a public-key/private-key pair.
     *
     * @param hSession the session's handle
     * @param pMechanism key-gen mechanism
     * @param pPublicKeyTemplate template for public key
     * @param ulPublicKeyAttributeCount number of public key attributes
     * @param pPrivateKeyTemplate template for private key
     * @param ulPrivateKeyAttributeCount number of private key attributes
     * @param phPublicKey pointer to public key handle
     * @param phPrivateKey pointer to private key handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GenerateKeyPair(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism,
                                  PKCS11Structures.CK_ATTRIBUTE[] pPublicKeyTemplate, NativeLong ulPublicKeyAttributeCount,
                                  PKCS11Structures.CK_ATTRIBUTE[] pPrivateKeyTemplate, NativeLong ulPrivateKeyAttributeCount,
                                  NativeLongByReference phPublicKey, NativeLongByReference phPrivateKey);

    /**
     * C_WrapKey wraps (encrypts) a key.
     *
     * @param hSession the session's handle
     * @param pMechanism the wrapping mechanism
     * @param hWrappingKey wrapping key
     * @param hKey key to be wrapped
     * @param pWrappedKey buffer for wrapped key (can be NULL)
     * @param pulWrappedKeyLen pointer to wrapped key length
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_WrapKey(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hWrappingKey, NativeLong hKey, byte[] pWrappedKey, NativeLongByReference pulWrappedKeyLen);

    /**
     * C_UnwrapKey unwraps (decrypts) a wrapped key.
     *
     * @param hSession the session's handle
     * @param pMechanism unwrapping mechanism
     * @param hUnwrappingKey unwrapping key
     * @param pWrappedKey the wrapped key
     * @param ulWrappedKeyLen wrapped key length
     * @param pTemplate new key template
     * @param ulAttributeCount template length
     * @param phKey pointer to unwrapped key handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_UnwrapKey(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hUnwrappingKey,
                           byte[] pWrappedKey, NativeLong ulWrappedKeyLen,
                           PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulAttributeCount,
                           NativeLongByReference phKey);

    /**
     * C_DeriveKey derives a key from a base key.
     *
     * @param hSession the session's handle
     * @param pMechanism key derivation mechanism
     * @param hBaseKey base key
     * @param pTemplate template for new key
     * @param ulAttributeCount template length
     * @param phKey pointer to derived key handle
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DeriveKey(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hBaseKey,
                           PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulAttributeCount,
                           NativeLongByReference phKey);

    // ========================================================================
    // Key Encapsulation Mechanism (KEM) functions - PKCS#11 v3.2
    // ========================================================================

    /**
     * C_EncapsulateKey generates a shared secret and encapsulates it for a recipient's public key.
     * This is used for KEM (Key Encapsulation Mechanism) operations such as ML-KEM.
     *
     * @param hSession the session's handle
     * @param pMechanism the encapsulation mechanism
     * @param hPublicKey handle of the recipient's public key
     * @param pTemplate template for the generated shared secret key
     * @param ulAttributeCount number of attributes in template
     * @param pCiphertext buffer for encapsulated ciphertext (can be NULL to get length)
     * @param pulCiphertextLen pointer to ciphertext length
     * @param phSharedSecret pointer to handle of generated shared secret key
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_EncapsulateKey(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hPublicKey,
                                PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulAttributeCount,
                                byte[] pCiphertext, NativeLongByReference pulCiphertextLen,
                                NativeLongByReference phSharedSecret);

    /**
     * C_DecapsulateKey decapsulates a shared secret using a private key.
     * This is used for KEM (Key Encapsulation Mechanism) operations such as ML-KEM.
     *
     * @param hSession the session's handle
     * @param pMechanism the decapsulation mechanism
     * @param hPrivateKey handle of the recipient's private key
     * @param pTemplate template for the recovered shared secret key
     * @param ulAttributeCount number of attributes in template
     * @param pCiphertext encapsulated ciphertext to decapsulate
     * @param ulCiphertextLen length of ciphertext
     * @param phSharedSecret pointer to handle of recovered shared secret key
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_DecapsulateKey(NativeLong hSession, PKCS11Structures.CK_MECHANISM pMechanism, NativeLong hPrivateKey,
                                PKCS11Structures.CK_ATTRIBUTE[] pTemplate, NativeLong ulAttributeCount,
                                byte[] pCiphertext, NativeLong ulCiphertextLen,
                                NativeLongByReference phSharedSecret);

    // ========================================================================
    // Random number generation functions
    // ========================================================================

    /**
     * C_SeedRandom mixes additional seed material into the token's RNG.
     *
     * @param hSession the session's handle
     * @param pSeed the seed material
     * @param ulSeedLen length of seed material
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_SeedRandom(NativeLong hSession, byte[] pSeed, NativeLong ulSeedLen);

    /**
     * C_GenerateRandom generates random data.
     *
     * @param hSession the session's handle
     * @param pRandomData buffer for random data
     * @param ulRandomLen length in bytes of random data
     * @return CKR_OK on success, error code otherwise
     */
    NativeLong C_GenerateRandom(NativeLong hSession, byte[] pRandomData, NativeLong ulRandomLen);
}

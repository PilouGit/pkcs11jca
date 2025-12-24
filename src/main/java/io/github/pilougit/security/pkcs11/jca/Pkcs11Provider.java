package io.github.pilougit.security.pkcs11.jca;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import io.github.pilougit.security.pkcs11.jca.mechanisms.Mechanism;
import io.github.pilougit.security.pkcs11.jca.mechanisms.MechanismFlagMapper;
import io.github.pilougit.security.pkcs11.jca.mechanisms.MechanismInfo;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Library;
import io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Structures;
import io.github.pilougit.security.pkcs11.jca.kem.PKCS11KEMSpi;
import io.github.pilougit.security.pkcs11.jca.kem.Pkcs11HybridKEMSpi;
import io.github.pilougit.security.pkcs11.jca.keygen.Pkcs11ECKeyPairGeneratorSpi;
import io.github.pilougit.security.pkcs11.jca.random.PKCS11SecureRandomSpi;

import java.security.Provider;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static io.github.pilougit.security.pkcs11.jca.util.jna.PKCS11Types.*;

public class Pkcs11Provider extends Provider {

    protected PKCS11Library pkcsS11Library;
    protected boolean configured;
    protected NativeLong slotID;
    protected NativeLong hSession;

    public Pkcs11Provider() {
        super("pkcs11Provider", "1.0", "PKCS#11 JCA Provider with post-quantum support");
        configured = false;
    }


    @Override
    public Provider configure(String libraryPath) {
        pkcsS11Library = PKCS11Library.getInstance(libraryPath);
        this.configured = true;
        return this;
    }

    public Provider configure(HsmOptions hsmOptions) {
        pkcsS11Library = PKCS11Library.getInstance(hsmOptions.pkcs11Library());

        // Initialize PKCS#11 library
        PKCS11Structures.CK_C_INITIALIZE_ARGS initArgs = new PKCS11Structures.CK_C_INITIALIZE_ARGS();
        initArgs.flags = new NativeLong(0);
        initArgs.pReserved = null;
        NativeLong rv = pkcsS11Library.C_Initialize(initArgs.getPointer());
        // Accept both CKR_OK and CKR_CRYPTOKI_ALREADY_INITIALIZED
        if (!rv.equals(CKR_OK) && !rv.equals(CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
            throw new RuntimeException("Failed to initialize PKCS#11 library. Error: " + rv.longValue());
        }

        // Determine slot ID to use
        slotID = determineSlotID(hsmOptions);

        // Open session
        NativeLongByReference phSession = new NativeLongByReference();
        NativeLong flags = new NativeLong(CKF_SERIAL_SESSION.longValue() | CKF_RW_SESSION.longValue());
        rv = pkcsS11Library.C_OpenSession(slotID, flags, null, null, phSession);
        if (!rv.equals(CKR_OK)) {
            throw new RuntimeException("Failed to open PKCS#11 session. Error: " + rv.longValue());
        }
        hSession = phSession.getValue();

        // Login if PIN is provided
        char[] userPin = hsmOptions.userPin();
        if (userPin != null && userPin.length > 0) {
            byte[] pinBytes = new String(userPin).getBytes();
            rv = pkcsS11Library.C_Login(hSession, CKU_USER, pinBytes, new NativeLong(pinBytes.length));
            Arrays.fill(pinBytes, (byte) 0); // Clear PIN from memory
            // Accept both CKR_OK and CKR_USER_ALREADY_LOGGED_IN
            if (!rv.equals(CKR_OK) && !rv.equals(CKR_USER_ALREADY_LOGGED_IN)) {
                throw new RuntimeException("Failed to login to PKCS#11 token. Error: " + rv.longValue());
            }
        }

        this.configured = true;

        // Register SecureRandom service
        registerSecureRandom();

        // Register KEM services
        registerKEM();

        return this;
    }

    private NativeLong determineSlotID(HsmOptions hsmOptions) {
        // If slot is explicitly specified, use it
        if (hsmOptions.slot().isPresent()) {
            return new NativeLong(hsmOptions.slot().get());
        }

        // If slotListIndex is specified, get that index from the slot list
        if (hsmOptions.slotListIndex().isPresent()) {
            NativeLongByReference pulCount = new NativeLongByReference();
            // First call to get count
            pkcsS11Library.C_GetSlotList((byte) 1, null, pulCount);
            int slotCount = pulCount.getValue().intValue();

            // Second call to get slot list
            NativeLong[] slotList = new NativeLong[slotCount];
            pkcsS11Library.C_GetSlotList((byte) 1, slotList, pulCount);

            int index = hsmOptions.slotListIndex().get();
            if (index >= slotCount) {
                throw new RuntimeException("Slot list index " + index + " out of bounds (only " + slotCount + " slots available)");
            }
            return slotList[index];
        }

        // If tokenLabel is specified, find slot with that label
        if (hsmOptions.tokenLabel().isPresent()) {
            NativeLongByReference pulCount = new NativeLongByReference();
            pkcsS11Library.C_GetSlotList((byte) 1, null, pulCount);
            int slotCount = pulCount.getValue().intValue();

            NativeLong[] slotList = new NativeLong[slotCount];
            pkcsS11Library.C_GetSlotList((byte) 1, slotList, pulCount);

            String targetLabel = hsmOptions.tokenLabel().get();
            for (NativeLong slot : slotList) {
                PKCS11Structures.CK_TOKEN_INFO tokenInfo = new PKCS11Structures.CK_TOKEN_INFO();
                pkcsS11Library.C_GetTokenInfo(slot, tokenInfo);
                String label = new String(tokenInfo.label).trim();
                if (label.equals(targetLabel)) {
                    return slot;
                }
            }
            throw new RuntimeException("Token with label '" + targetLabel + "' not found");
        }

        // Default: use first available slot with token
        NativeLongByReference pulCount = new NativeLongByReference();
        pkcsS11Library.C_GetSlotList((byte) 1, null, pulCount);
        int slotCount = pulCount.getValue().intValue();

        if (slotCount == 0) {
            throw new RuntimeException("No PKCS#11 slots with tokens found");
        }

        NativeLong[] slotList = new NativeLong[slotCount];
        pkcsS11Library.C_GetSlotList((byte) 1, slotList, pulCount);

        return slotList[0];
    }
    public Pkcs11Info getPkcs11Info() {
        PKCS11Structures.CK_INFO info = new PKCS11Structures.CK_INFO();

        NativeLong result = pkcsS11Library.C_GetInfo(info);
        return Pkcs11Info.from(info);
    }
    public Set<Mechanism> getMechanisms(long slotId) {

        NativeLongByReference count = new NativeLongByReference();

        pkcsS11Library.C_GetMechanismList(
                new NativeLong(slotId),
                null,
                count
        );

        int size = count.getValue().intValue();
        NativeLong[] buffer = new NativeLong[size];

        pkcsS11Library.C_GetMechanismList(
                new NativeLong(slotId),
                buffer,
                count
        );

        return Arrays.stream(buffer)
                .map(NativeLong::longValue)
                .map(Mechanism::from)
                .collect(Collectors.toUnmodifiableSet());
    }
    public MechanismInfo getMechanismInfo(long slotId, Mechanism mechanism) {

        PKCS11Structures.CK_MECHANISM_INFO info = new PKCS11Structures.CK_MECHANISM_INFO();

        pkcsS11Library.C_GetMechanismInfo(
                new NativeLong(slotId),
                new NativeLong(mechanism.value()),
                info
        );

        return new MechanismInfo(
                info.ulMinKeySize.intValue(),
                info.ulMaxKeySize.intValue(),
                MechanismFlagMapper.from(info.flags.longValue())
        );
    }
    private void registerSecureRandom() {
        putService(new Service(this, "SecureRandom", "PKCS11",
                PKCS11SecureRandomSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11SecureRandomSpi(pkcsS11Library,hSession);
            }
        });
    }

    private void regissterECC()
    {
        putService(new Service(this, "KEM", "ML-KEM-512",
                Pkcs11ECKeyPairGeneratorSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11KEMSpi(pkcsS11Library, hSession, "ML-KEM-512");
            }
        });
    }
    private void registerKEM() {
        // Register ML-KEM-512
        putService(new Service(this, "KEM", "ML-KEM-512",
                PKCS11KEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11KEMSpi(pkcsS11Library, hSession, "ML-KEM-512");
            }
        });

        // Register ML-KEM-768
        putService(new Service(this, "KEM", "ML-KEM-768",
                PKCS11KEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11KEMSpi(pkcsS11Library, hSession, "ML-KEM-768");
            }
        });

        // Register ML-KEM-1024
        putService(new Service(this, "KEM", "ML-KEM-1024",
                PKCS11KEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11KEMSpi(pkcsS11Library, hSession, "ML-KEM-1024");
            }
        });

        // Register aliases for Kyber
        putService(new Service(this, "KEM", "KYBER512",
                PKCS11KEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11KEMSpi(pkcsS11Library, hSession, "KYBER512");
            }
        });

        putService(new Service(this, "KEM", "KYBER768",
                PKCS11KEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11KEMSpi(pkcsS11Library, hSession, "KYBER768");
            }
        });

        putService(new Service(this, "KEM", "KYBER1024",
                PKCS11KEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PKCS11KEMSpi(pkcsS11Library, hSession, "KYBER1024");
            }
        });

        // Register Hybrid KEM services
        registerHybridKEM();
    }

    private void registerHybridKEM() {
        // SoftHSMv2 vendor-specific hybrid KEM mechanisms
        // These use native PKCS#11 mechanisms for defense-in-depth security

        // X25519 + ML-KEM-768 (recommended for general use)
        putService(new Service(this, "KEM", "X25519-ML-KEM-768",
                Pkcs11HybridKEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Pkcs11HybridKEMSpi(pkcsS11Library, hSession, "X25519-ML-KEM-768");
            }
        });

        // ECDH P-256 + ML-KEM-768
        putService(new Service(this, "KEM", "ECDH-P256-ML-KEM-768",
                Pkcs11HybridKEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Pkcs11HybridKEMSpi(pkcsS11Library, hSession, "ECDH-P256-ML-KEM-768");
            }
        });

        // ECDH P-384 + ML-KEM-1024
        putService(new Service(this, "KEM", "ECDH-P384-ML-KEM-1024",
                Pkcs11HybridKEMSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new Pkcs11HybridKEMSpi(pkcsS11Library, hSession, "ECDH-P384-ML-KEM-1024");
            }
        });
    }

    @Override
    public boolean isConfigured() {
        return configured;
    }

    public NativeLong getSlotID() {
        return slotID;
    }

    public NativeLong getSession() {
        return hSession;
    }

    /**
     * Cleanup PKCS#11 resources.
     * Closes the session and logs out the user.
     */
    public void cleanup() {
        if (hSession != null && pkcsS11Library != null) {
            try {
                // Logout
                pkcsS11Library.C_Logout(hSession);
            } catch (Exception e) {
                // Ignore logout errors
            }

            try {
                // Close session
                pkcsS11Library.C_CloseSession(hSession);
            } catch (Exception e) {
                // Ignore close session errors
            }

            hSession = null;
        }
    }

    /**
     * Finalize the PKCS#11 library.
     * This should only be called when the library is no longer needed.
     */
    public void finalizePKCS11() {
        cleanup();
        if (pkcsS11Library != null) {
            try {
                pkcsS11Library.C_Finalize(null);
            } catch (Exception e) {
                // Ignore finalize errors
            }
        }
    }
}

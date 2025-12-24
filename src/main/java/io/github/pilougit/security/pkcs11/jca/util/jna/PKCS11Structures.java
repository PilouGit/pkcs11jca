package io.github.pilougit.security.pkcs11.jca.util.jna;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * PKCS#11 structures mapped to Java using JNA.
 * Based on PKCS#11 v3.2 specification.
 */
public class PKCS11Structures {

    /**
     * CK_VERSION structure
     */
    public static class CK_VERSION extends Structure {
        public byte major;
        public byte minor;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("major", "minor");
        }
    }

    /**
     * CK_INFO structure
     */
    public static class CK_INFO extends Structure {
        public CK_VERSION cryptokiVersion;
        public byte[] manufacturerID = new byte[32];
        public NativeLong flags;
        public byte[] libraryDescription = new byte[32];
        public CK_VERSION libraryVersion;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("cryptokiVersion", "manufacturerID", "flags",
                               "libraryDescription", "libraryVersion");
        }
    }

    /**
     * CK_SLOT_INFO structure
     */
    public static class CK_SLOT_INFO extends Structure {
        public byte[] slotDescription = new byte[64];
        public byte[] manufacturerID = new byte[32];
        public NativeLong flags;
        public CK_VERSION hardwareVersion;
        public CK_VERSION firmwareVersion;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("slotDescription", "manufacturerID", "flags",
                               "hardwareVersion", "firmwareVersion");
        }
    }

    /**
     * CK_TOKEN_INFO structure
     */
    public static class CK_TOKEN_INFO extends Structure {
        public byte[] label = new byte[32];
        public byte[] manufacturerID = new byte[32];
        public byte[] model = new byte[16];
        public byte[] serialNumber = new byte[16];
        public NativeLong flags;
        public NativeLong ulMaxSessionCount;
        public NativeLong ulSessionCount;
        public NativeLong ulMaxRwSessionCount;
        public NativeLong ulRwSessionCount;
        public NativeLong ulMaxPinLen;
        public NativeLong ulMinPinLen;
        public NativeLong ulTotalPublicMemory;
        public NativeLong ulFreePublicMemory;
        public NativeLong ulTotalPrivateMemory;
        public NativeLong ulFreePrivateMemory;
        public CK_VERSION hardwareVersion;
        public CK_VERSION firmwareVersion;
        public byte[] utcTime = new byte[16];

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("label", "manufacturerID", "model", "serialNumber",
                               "flags", "ulMaxSessionCount", "ulSessionCount",
                               "ulMaxRwSessionCount", "ulRwSessionCount", "ulMaxPinLen",
                               "ulMinPinLen", "ulTotalPublicMemory", "ulFreePublicMemory",
                               "ulTotalPrivateMemory", "ulFreePrivateMemory",
                               "hardwareVersion", "firmwareVersion", "utcTime");
        }
    }

    /**
     * CK_SESSION_INFO structure
     */
    public static class CK_SESSION_INFO extends Structure {
        public NativeLong slotID;
        public NativeLong state;
        public NativeLong flags;
        public NativeLong ulDeviceError;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("slotID", "state", "flags", "ulDeviceError");
        }
    }

    /**
     * CK_ATTRIBUTE structure
     */
    public static class CK_ATTRIBUTE extends Structure {
        public NativeLong type;
        public Pointer pValue;
        public NativeLong ulValueLen;

        public CK_ATTRIBUTE() {
            super();
        }

        public CK_ATTRIBUTE(NativeLong type, Pointer pValue, NativeLong ulValueLen) {
            this.type = type;
            this.pValue = pValue;
            this.ulValueLen = ulValueLen;
        }
        public static CK_ATTRIBUTE createByteArrayAttr(long type, byte[] value) {
            return createByteArrayAttr(new NativeLong(type),value);
        }
        public static CK_ATTRIBUTE createByteArrayAttr(NativeLong type, byte[] value) {
            Memory mem = new Memory(value.length);
            mem.write(0, value, 0, value.length);
            return new CK_ATTRIBUTE(type, mem, new NativeLong(value.length));
        }

        public static CK_ATTRIBUTE createLongAttr(long type, long value) {

            return createLongAttr(new NativeLong(type), value);
        }
        public static CK_ATTRIBUTE createLongAttr(NativeLong type, long value) {
            Memory mem = new Memory(Long.BYTES);
            mem.setLong(0, value);
            return new CK_ATTRIBUTE(type, mem, new NativeLong(Long.BYTES));
        }
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("type", "pValue", "ulValueLen");
        }
    }

    /**
     * CK_DATE structure
     */
    public static class CK_DATE extends Structure {
        public byte[] year = new byte[4];
        public byte[] month = new byte[2];
        public byte[] day = new byte[2];

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("year", "month", "day");
        }
    }

    /**
     * CK_MECHANISM structure
     */
    public static class CK_MECHANISM extends Structure {
        public NativeLong mechanism;
        public Pointer pParameter;
        public NativeLong ulParameterLen;

        public CK_MECHANISM() {
            super();
        }

        public CK_MECHANISM(NativeLong mechanism) {
            this.mechanism = mechanism;
            this.pParameter = null;
            this.ulParameterLen = new NativeLong(0);
        }

        public CK_MECHANISM(NativeLong mechanism, Pointer pParameter, NativeLong ulParameterLen) {
            this.mechanism = mechanism;
            this.pParameter = pParameter;
            this.ulParameterLen = ulParameterLen;
        }

        public static CK_MECHANISM ecKeyPairGen(byte[] ecOidDer) {
            Pointer p = new com.sun.jna.Memory(ecOidDer.length);
            p.write(0, ecOidDer, 0, ecOidDer.length);
            return new CK_MECHANISM(
                    PKCS11Mechanisms.CKM_EC_KEY_PAIR_GEN,
                    p,
                    new NativeLong(ecOidDer.length)
            );
        }
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("mechanism", "pParameter", "ulParameterLen");
        }
    }

    /**
     * CK_MECHANISM_INFO structure
     */
    public static class CK_MECHANISM_INFO extends Structure {
        public NativeLong ulMinKeySize;
        public NativeLong ulMaxKeySize;
        public NativeLong flags;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("ulMinKeySize", "ulMaxKeySize", "flags");
        }
    }

    /**
     * CK_C_INITIALIZE_ARGS structure
     */
    public static class CK_C_INITIALIZE_ARGS extends Structure {
        public Pointer CreateMutex;
        public Pointer DestroyMutex;
        public Pointer LockMutex;
        public Pointer UnlockMutex;
        public NativeLong flags;
        public Pointer pReserved;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("CreateMutex", "DestroyMutex", "LockMutex",
                               "UnlockMutex", "flags", "pReserved");
        }
    }

    /**
     * CK_RSA_PKCS_OAEP_PARAMS structure
     */
    public static class CK_RSA_PKCS_OAEP_PARAMS extends Structure {
        public NativeLong hashAlg;
        public NativeLong mgf;
        public NativeLong source;
        public Pointer pSourceData;
        public NativeLong ulSourceDataLen;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("hashAlg", "mgf", "source", "pSourceData", "ulSourceDataLen");
        }
    }

    /**
     * CK_RSA_PKCS_PSS_PARAMS structure
     */
    public static class CK_RSA_PKCS_PSS_PARAMS extends Structure {
        public NativeLong hashAlg;
        public NativeLong mgf;
        public NativeLong sLen;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("hashAlg", "mgf", "sLen");
        }
    }

    /**
     * CK_ECDH1_DERIVE_PARAMS structure
     */
    public static class CK_ECDH1_DERIVE_PARAMS extends Structure {
        public NativeLong kdf;
        public NativeLong ulSharedDataLen;
        public Pointer pSharedData;
        public NativeLong ulPublicDataLen;
        public Pointer pPublicData;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("kdf", "ulSharedDataLen", "pSharedData",
                               "ulPublicDataLen", "pPublicData");
        }
    }

    /**
     * CK_AES_GCM_PARAMS structure
     */
    public static class CK_AES_GCM_PARAMS extends Structure {
        public Pointer pIv;
        public NativeLong ulIvLen;
        public NativeLong ulIvBits;
        public Pointer pAAD;
        public NativeLong ulAADLen;
        public NativeLong ulTagBits;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("pIv", "ulIvLen", "ulIvBits", "pAAD", "ulAADLen", "ulTagBits");
        }
    }

    /**
     * CK_GCM_PARAMS structure (alias for CK_AES_GCM_PARAMS)
     */
    public static class CK_GCM_PARAMS extends CK_AES_GCM_PARAMS {
    }
}

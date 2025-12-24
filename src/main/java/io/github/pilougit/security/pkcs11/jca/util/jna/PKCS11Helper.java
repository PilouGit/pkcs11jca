package io.github.pilougit.security.pkcs11.jca.util.jna;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;

/**
 * Helper class providing utility methods for common PKCS#11 operations.
 * This class simplifies working with the low-level JNA interface.
 */
public class PKCS11Helper {

    /**
     * Convert a Java String to a PKCS#11 padded byte array.
     *
     * @param str The string to convert
     * @param length The desired length (will be padded with spaces)
     * @return Padded byte array
     */
    public static byte[] toPaddedByteArray(String str, int length) {
        byte[] result = new byte[length];
        byte[] strBytes = str.getBytes();
        int copyLen = Math.min(strBytes.length, length);
        System.arraycopy(strBytes, 0, result, 0, copyLen);
        // Pad with spaces
        for (int i = copyLen; i < length; i++) {
            result[i] = ' ';
        }
        return result;
    }

    /**
     * Convert a PKCS#11 byte array to a trimmed Java String.
     *
     * @param bytes The byte array
     * @return Trimmed string
     */
    public static String fromPaddedByteArray(byte[] bytes) {
        return new String(bytes).trim();
    }

    /**
     * Create a CK_ATTRIBUTE for a boolean value.
     *
     * @param type Attribute type
     * @param value Boolean value
     * @return CK_ATTRIBUTE structure
     */
    public static PKCS11Structures.CK_ATTRIBUTE createBooleanAttribute(NativeLong type, boolean value) {
        Memory mem = new Memory(1);
        mem.setByte(0, value ? PKCS11Types.CK_TRUE : PKCS11Types.CK_FALSE);
        return new PKCS11Structures.CK_ATTRIBUTE(type, mem, new NativeLong(1));
    }

    /**
     * Create a CK_ATTRIBUTE for a NativeLong value.
     *
     * @param type Attribute type
     * @param value NativeLong value
     * @return CK_ATTRIBUTE structure
     */
    public static PKCS11Structures.CK_ATTRIBUTE createNativeLongAttribute(NativeLong type, NativeLong value) {
        Memory mem = new Memory(NativeLong.SIZE);
        mem.setNativeLong(0, value);
        return new PKCS11Structures.CK_ATTRIBUTE(type, mem, new NativeLong(NativeLong.SIZE));
    }

    /**
     * Create a CK_ATTRIBUTE for a byte array value.
     *
     * @param type Attribute type
     * @param value Byte array value
     * @return CK_ATTRIBUTE structure
     */
    public static PKCS11Structures.CK_ATTRIBUTE createByteArrayAttribute(NativeLong type, byte[] value) {
        if (value == null || value.length == 0) {
            return new PKCS11Structures.CK_ATTRIBUTE(type, null, new NativeLong(0));
        }
        Memory mem = new Memory(value.length);
        mem.write(0, value, 0, value.length);
        return new PKCS11Structures.CK_ATTRIBUTE(type, mem, new NativeLong(value.length));
    }

    /**
     * Create a CK_ATTRIBUTE for querying attribute length (pValue = NULL).
     *
     * @param type Attribute type
     * @return CK_ATTRIBUTE structure
     */
    public static PKCS11Structures.CK_ATTRIBUTE createQueryAttribute(NativeLong type) {
        return new PKCS11Structures.CK_ATTRIBUTE(type, null, new NativeLong(-1));
    }

    /**
     * Check if a return value indicates success.
     *
     * @param rv Return value from PKCS#11 function
     * @return true if successful
     */
    public static boolean isSuccess(NativeLong rv) {
        return rv.equals(PKCS11Types.CKR_OK);
    }

    /**
     * Throw an exception if the return value indicates failure.
     *
     * @param rv Return value from PKCS#11 function
     * @param operation Description of the operation
     * @throws PKCS11Exception if the operation failed
     */
    public static void checkResult(NativeLong rv, String operation) throws PKCS11Exception {
        if (!isSuccess(rv)) {
            throw new PKCS11Exception(operation + " failed with error code: 0x" +
                Long.toHexString(rv.longValue()), rv);
        }
    }

    /**
     * Get the error name for a return value.
     *
     * @param rv Return value
     * @return Error name or hex string
     */
    public static String getErrorName(NativeLong rv) {
        long code = rv.longValue();

        if (code == PKCS11Types.CKR_OK.longValue()) return "CKR_OK";
        if (code == PKCS11Types.CKR_CANCEL.longValue()) return "CKR_CANCEL";
        if (code == PKCS11Types.CKR_HOST_MEMORY.longValue()) return "CKR_HOST_MEMORY";
        if (code == PKCS11Types.CKR_SLOT_ID_INVALID.longValue()) return "CKR_SLOT_ID_INVALID";
        if (code == PKCS11Types.CKR_GENERAL_ERROR.longValue()) return "CKR_GENERAL_ERROR";
        if (code == PKCS11Types.CKR_FUNCTION_FAILED.longValue()) return "CKR_FUNCTION_FAILED";
        if (code == PKCS11Types.CKR_ARGUMENTS_BAD.longValue()) return "CKR_ARGUMENTS_BAD";
        if (code == PKCS11Types.CKR_ATTRIBUTE_READ_ONLY.longValue()) return "CKR_ATTRIBUTE_READ_ONLY";
        if (code == PKCS11Types.CKR_ATTRIBUTE_SENSITIVE.longValue()) return "CKR_ATTRIBUTE_SENSITIVE";
        if (code == PKCS11Types.CKR_ATTRIBUTE_TYPE_INVALID.longValue()) return "CKR_ATTRIBUTE_TYPE_INVALID";
        if (code == PKCS11Types.CKR_ATTRIBUTE_VALUE_INVALID.longValue()) return "CKR_ATTRIBUTE_VALUE_INVALID";
        if (code == PKCS11Types.CKR_DATA_INVALID.longValue()) return "CKR_DATA_INVALID";
        if (code == PKCS11Types.CKR_DEVICE_ERROR.longValue()) return "CKR_DEVICE_ERROR";
        if (code == PKCS11Types.CKR_DEVICE_MEMORY.longValue()) return "CKR_DEVICE_MEMORY";
        if (code == PKCS11Types.CKR_DEVICE_REMOVED.longValue()) return "CKR_DEVICE_REMOVED";
        if (code == PKCS11Types.CKR_FUNCTION_NOT_SUPPORTED.longValue()) return "CKR_FUNCTION_NOT_SUPPORTED";
        if (code == PKCS11Types.CKR_KEY_HANDLE_INVALID.longValue()) return "CKR_KEY_HANDLE_INVALID";
        if (code == PKCS11Types.CKR_MECHANISM_INVALID.longValue()) return "CKR_MECHANISM_INVALID";
        if (code == PKCS11Types.CKR_MECHANISM_PARAM_INVALID.longValue()) return "CKR_MECHANISM_PARAM_INVALID";
        if (code == PKCS11Types.CKR_OBJECT_HANDLE_INVALID.longValue()) return "CKR_OBJECT_HANDLE_INVALID";
        if (code == PKCS11Types.CKR_OPERATION_ACTIVE.longValue()) return "CKR_OPERATION_ACTIVE";
        if (code == PKCS11Types.CKR_OPERATION_NOT_INITIALIZED.longValue()) return "CKR_OPERATION_NOT_INITIALIZED";
        if (code == PKCS11Types.CKR_PIN_INCORRECT.longValue()) return "CKR_PIN_INCORRECT";
        if (code == PKCS11Types.CKR_PIN_INVALID.longValue()) return "CKR_PIN_INVALID";
        if (code == PKCS11Types.CKR_PIN_LEN_RANGE.longValue()) return "CKR_PIN_LEN_RANGE";
        if (code == PKCS11Types.CKR_PIN_EXPIRED.longValue()) return "CKR_PIN_EXPIRED";
        if (code == PKCS11Types.CKR_PIN_LOCKED.longValue()) return "CKR_PIN_LOCKED";
        if (code == PKCS11Types.CKR_SESSION_CLOSED.longValue()) return "CKR_SESSION_CLOSED";
        if (code == PKCS11Types.CKR_SESSION_HANDLE_INVALID.longValue()) return "CKR_SESSION_HANDLE_INVALID";
        if (code == PKCS11Types.CKR_SESSION_READ_ONLY.longValue()) return "CKR_SESSION_READ_ONLY";
        if (code == PKCS11Types.CKR_SIGNATURE_INVALID.longValue()) return "CKR_SIGNATURE_INVALID";
        if (code == PKCS11Types.CKR_TOKEN_NOT_PRESENT.longValue()) return "CKR_TOKEN_NOT_PRESENT";
        if (code == PKCS11Types.CKR_TOKEN_NOT_RECOGNIZED.longValue()) return "CKR_TOKEN_NOT_RECOGNIZED";
        if (code == PKCS11Types.CKR_USER_ALREADY_LOGGED_IN.longValue()) return "CKR_USER_ALREADY_LOGGED_IN";
        if (code == PKCS11Types.CKR_USER_NOT_LOGGED_IN.longValue()) return "CKR_USER_NOT_LOGGED_IN";
        if (code == PKCS11Types.CKR_USER_PIN_NOT_INITIALIZED.longValue()) return "CKR_USER_PIN_NOT_INITIALIZED";
        if (code == PKCS11Types.CKR_USER_TYPE_INVALID.longValue()) return "CKR_USER_TYPE_INVALID";
        if (code == PKCS11Types.CKR_BUFFER_TOO_SMALL.longValue()) return "CKR_BUFFER_TOO_SMALL";
        if (code == PKCS11Types.CKR_CRYPTOKI_NOT_INITIALIZED.longValue()) return "CKR_CRYPTOKI_NOT_INITIALIZED";
        if (code == PKCS11Types.CKR_CRYPTOKI_ALREADY_INITIALIZED.longValue()) return "CKR_CRYPTOKI_ALREADY_INITIALIZED";

        return "Unknown error (0x" + Long.toHexString(code) + ")";
    }

    /**
     * Custom exception for PKCS#11 errors.
     */
    public static class PKCS11Exception extends Exception {
        private final NativeLong errorCode;

        public PKCS11Exception(String message, NativeLong errorCode) {
            super(message + " [" + getErrorName(errorCode) + "]");
            this.errorCode = errorCode;
        }

        public NativeLong getErrorCode() {
            return errorCode;
        }
    }


}

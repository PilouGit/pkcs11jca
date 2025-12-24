package io.github.pilougit.security.pkcs11.jca.util.jna;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;

public class CKAttributeBuilder {

    private final PKCS11Structures.CK_ATTRIBUTE[] attrs;
    private final Memory backingMemory;
    private int offset = 0;

    public CKAttributeBuilder(int count, int totalValueBytes) {
        attrs = (PKCS11Structures.CK_ATTRIBUTE[]) new PKCS11Structures.CK_ATTRIBUTE().toArray(count);
        backingMemory = new Memory(totalValueBytes); // bloc contigu pour toutes les valeurs
    }

    public void setBoolean(int index, NativeLong type, boolean value) {
        PKCS11Structures.CK_ATTRIBUTE attr = attrs[index];
        attr.type = type;
        attr.pValue = backingMemory.share(offset, 1);
        attr.pValue.setByte(0, (byte) (value ? 1 : 0));
        attr.ulValueLen = new NativeLong(1);
        attr.write();
        offset += 1;
    }

    public void setNativeLong(int index, NativeLong type, long value) {
        PKCS11Structures.CK_ATTRIBUTE attr = attrs[index];
        attr.type = type;
        attr.pValue = backingMemory.share(offset, NativeLong.SIZE);
        attr.pValue.setNativeLong(0, new NativeLong(value));
        attr.ulValueLen = new NativeLong(NativeLong.SIZE);
        attr.write();
        offset += NativeLong.SIZE;
    }

    public void setByteArray(int index, NativeLong type, byte[] data) {
        PKCS11Structures.CK_ATTRIBUTE attr = attrs[index];
        attr.type = type;
        attr.pValue = backingMemory.share(offset, data.length);
        attr.pValue.write(0, data, 0, data.length);
        attr.ulValueLen = new NativeLong(data.length);
        attr.write();
        offset += data.length;
    }

    public PKCS11Structures.CK_ATTRIBUTE[] build() {
        return attrs;
    }
}
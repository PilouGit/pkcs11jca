package io.github.pilougit.security.pkcs11.jca;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

public class HsmOptions {

    private final String name;
    private final Path pkcs11Library;

    // --- Slot / Token ---
    private final Long slot;
    private final Integer slotListIndex;
    private final String tokenLabel;

    // --- Authentification ---
    private final char[] userPin;

    public HsmOptions(Builder builder) {
        this.name = Objects.requireNonNull(builder.name);
        this.pkcs11Library = Objects.requireNonNull(builder.pkcs11Library);
        this.slot = builder.slot;
        this.slotListIndex = builder.slotListIndex;
        this.tokenLabel = builder.tokenLabel;
        this.userPin = Objects.requireNonNull(builder.userPin);
    }
    public String name() { return name; }
    public Path pkcs11Library() { return pkcs11Library; }
    public Optional<Long> slot() { return Optional.ofNullable(slot); }
    public Optional<Integer> slotListIndex() { return Optional.ofNullable(slotListIndex); }
    public Optional<String> tokenLabel() { return Optional.ofNullable(tokenLabel); }
    public char[] userPin() { return userPin; }


    public static class Builder {
        private String name;
        private Path pkcs11Library;
        private Long slot;
        private Integer slotListIndex;
        private String tokenLabel;
        private char[] userPin;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder pkcs11Library(Path path) {
            this.pkcs11Library = path;
            return this;
        }

        public Builder slot(long slot) {
            this.slot = slot;
            return this;
        }

        public Builder slotListIndex(Integer index) {
            this.slotListIndex = index;
            return this;
        }

        public Builder tokenLabel(String label) {
            this.tokenLabel = label;
            return this;
        }

        public Builder userPin(char[] pin) {
            this.userPin = pin;
            return this;
        }



        public HsmOptions build() {
            return new HsmOptions(this);
        }
    }
}

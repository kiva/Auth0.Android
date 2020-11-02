package com.auth0.android.authentication.storage;

/**
 * Exception thrown by the {@link CryptoUtil} class whenever the Keys are deemed invalid
 * and so the content encrypted with them unrecoverable.
 */
class IncompatibleDeviceException extends CryptoException {
    IncompatibleDeviceException(Throwable cause) {
        super(String.format("The device is not compatible with the %s class.", CryptoUtil.class.getSimpleName()), cause);
    }
}

/**
 * Exception thrown by the {@link CryptoUtil} class when the the legacy key aliases are in use.
 * They must be migrated to the new key alias pattern.
 */
class NeedsMigrationException extends CryptoException {
    private final byte[] legacyData;

    NeedsMigrationException(byte[] legacyDecryptedInput) {
        super("Credentials require migration to new key alias.", null);
        this.legacyData = legacyDecryptedInput;
    }

    public byte[] getLegacyEncodedData() {
        return this.legacyData;
    }
}

package com.auth0.android.authentication.storage;

import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by lbalmaceda on 8/24/17.
 * Class to handle encryption/decryption cryptographic operations using AES and RSA algorithms in devices with API 19 or higher.
 */
@SuppressWarnings("WeakerAccess")
@RequiresApi(api = Build.VERSION_CODES.KITKAT)
class CryptoUtil {

    private static final String TAG = CryptoUtil.class.getSimpleName();

    // Transformations available since API 18
    // https://developer.android.com/training/articles/keystore.html#SupportedCiphers
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    // https://developer.android.com/reference/javax/crypto/Cipher.html
    @SuppressWarnings("SpellCheckingInspection")
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM_AES = "AES";
    private static final int AES_KEY_SIZE = 256;

    private final String KEY_ALIAS;
    private final String KEY_IV_ALIAS;
    private final Storage storage;
    private final KeyStoreUtil keyStoreUtil;


    public CryptoUtil(@NonNull Context context, @NonNull Storage storage, @NonNull String keyAlias) {
        keyAlias = keyAlias.trim();
        if (TextUtils.isEmpty(keyAlias)) {
            throw new IllegalArgumentException("RSA and AES Key alias must be valid.");
        }
        this.KEY_ALIAS = context.getPackageName() + "." + keyAlias;
        this.KEY_IV_ALIAS = context.getPackageName() + "." + keyAlias + "_iv";
        this.storage = storage;
        this.keyStoreUtil = new KeyStoreUtil(context, keyAlias);
    }

    /**
     * Attempts to recover the existing RSA Private Key entry or generates a new one as secure as
     * this device and Android version allows it if none is found.
     *
     * @return a valid RSA Private Key entry
     * @throws CryptoException             if the stored keys can't be recovered and should be deemed invalid
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required by this method
     */
    @VisibleForTesting
    KeyStore.PrivateKeyEntry getRSAKeyEntry() throws CryptoException, IncompatibleDeviceException {
        return getRSAKeyEntry(KEY_ALIAS);
    }

    @VisibleForTesting
    KeyStore.PrivateKeyEntry getRSAKeyEntry(@NonNull String keyAlias) throws CryptoException, IncompatibleDeviceException {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            if (keyStore.containsAlias(keyAlias)) {
                //Return existing key. On weird cases, the alias would be present but the key not
                KeyStore.PrivateKeyEntry existingKey = keyStoreUtil.getKeyEntryCompat(keyStore, keyAlias);
                if (existingKey != null) {
                    return existingKey;
                }
            }

            // use only the new key alias when generating a new key store
            keyStoreUtil.generateKeyStore(KEY_ALIAS);
            return keyStoreUtil.getKeyEntryCompat(keyStore, KEY_ALIAS);
        } catch (CertificateException | InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException | KeyStoreException | ProviderException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - CertificateException:
             *      Thrown when certificate has expired (25 years..) or couldn't be loaded
             * - KeyStoreException:
             * - NoSuchProviderException:
             *      Thrown when "AndroidKeyStore" is not available. Was introduced on API 18.
             * - NoSuchAlgorithmException:
             *      Thrown when "RSA" algorithm is not available. Was introduced on API 18.
             * - InvalidAlgorithmParameterException:
             *      Thrown if Key Size is other than 512, 768, 1024, 2048, 3072, 4096
             *      or if Padding is other than RSA/ECB/PKCS1Padding, introduced on API 18
             *      or if Block Mode is other than ECB
             * - ProviderException:
             *      Thrown on some modified devices when KeyPairGenerator#generateKeyPair is called.
             *      See: https://www.bountysource.com/issues/45527093-keystore-issues
             *
             * However if any of this exceptions happens to be thrown (OEMs often change their Android distribution source code),
             * all the checks performed in this class wouldn't matter and the device would not be compatible at all with it.
             *
             * Read more in https://developer.android.com/training/articles/keystore#SupportedAlgorithms
             */
            Log.e(TAG, "The device can't generate a new RSA Key pair.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IOException | UnrecoverableEntryException e) {
            /*
             * Any of this exceptions mean the old key pair is somehow corrupted.
             * We can delete both the RSA and the AES keys and let the user retry the operation.
             *
             * - IOException:
             *      Thrown when there is an I/O or format problem with the keystore data.
             * - UnrecoverableEntryException:
             *      Thrown when the key cannot be recovered. Probably because it was invalidated by a Lock Screen change.
             */
            deleteRSAKeys();
            deleteAESKeys();
            throw new CryptoException("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", e);
        }

    }

    /**
     * Removes the RSA keys generated in a previous execution.
     * Used when we want the next call to {@link #encrypt(byte[])} or {@link #decrypt(byte[])}
     * to recreate the keys.
     */
    private void deleteRSAKeys() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_ALIAS);
            if (keyStore.containsAlias(keyStoreUtil.legacyKeyAlias())) {
                keyStore.deleteEntry(keyStoreUtil.legacyKeyAlias());
            }
            Log.d(TAG, "Deleting the existing RSA key pair from the KeyStore.");
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to remove the RSA KeyEntry from the Android KeyStore.", e);
        }
    }

    /**
     * Removes the AES keys generated in a previous execution.
     * Used when we want the next call to {@link #encrypt(byte[])} or {@link #decrypt(byte[])}
     * to recreate the keys.
     */
    private void deleteAESKeys() {
        storage.remove(KEY_ALIAS);
        storage.remove(KEY_IV_ALIAS);
        storage.remove(keyStoreUtil.legacyKeyAlias());
        storage.remove(keyStoreUtil.legacyKeyIVAlias());
    }

    /**
     * Decrypts the given input using a generated RSA Private Key.
     * Used to decrypt the AES key for later usage.
     *
     * @param encryptedInput the input bytes to decrypt
     * @return the decrypted bytes output
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     * @throws CryptoException             if the stored RSA keys can't be recovered and should be deemed invalid
     */
    @VisibleForTesting
    byte[] RSADecrypt(byte[] encryptedInput) throws IncompatibleDeviceException, CryptoException {
        try {
            final boolean hasLegacyEntry = keyStoreUtil.hasLegacyCredential()
                && !TextUtils.isEmpty(storage.retrieveString(keyStoreUtil.legacyKeyIVAlias()));
            final String keyAlias;
            if (hasLegacyEntry) {
                keyAlias = keyStoreUtil.legacyKeyAlias();
            } else {
                keyAlias = KEY_ALIAS;
            }

            PrivateKey privateKey = getRSAKeyEntry(keyAlias).getPrivateKey();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if PKCS1Padding is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "The device can't decrypt input using a RSA Key.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IllegalArgumentException | IllegalBlockSizeException | BadPaddingException e) {
            /*
             * Any of this exceptions mean the encrypted input is somehow corrupted and cannot be recovered.
             * Delete the AES keys since those originated the input.
             *
             * - IllegalBlockSizeException:
             *      Thrown only on encrypt mode.
             * - BadPaddingException:
             *      Thrown if the input doesn't contain the proper padding bytes.
             * - IllegalArgumentException
             *      Thrown when doFinal is called with a null input.
             */
            deleteAESKeys();
            throw new CryptoException("The RSA encrypted input is corrupted and cannot be recovered. Please discard it.", e);
        }

    }

    /**
     * Encrypts the given input using a generated RSA Public Key.
     * Used to encrypt the AES key for later storage.
     *
     * @param decryptedInput the input bytes to encrypt
     * @return the encrypted bytes output
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     * @throws CryptoException             if the stored RSA keys can't be recovered and should be deemed invalid
     */
    @VisibleForTesting
    byte[] RSAEncrypt(byte[] decryptedInput) throws IncompatibleDeviceException, CryptoException {
        try {
            Certificate certificate = getRSAKeyEntry().getCertificate();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            final byte[] decrypted = cipher.doFinal(decryptedInput);
            return decrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if PKCS1Padding is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "The device can't encrypt input using a RSA Key.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            /*
             * They really should not be thrown at all since padding is requested in the transformation.
             * Delete the AES keys since those originated the input.
             *
             * - IllegalBlockSizeException:
             *      Thrown if no padding has been requested and the length is not multiple of block size.
             * - BadPaddingException:
             *      Thrown only on decrypt mode.
             */
            deleteAESKeys();
            throw new CryptoException("The RSA decrypted input is invalid.", e);
        }

    }

    /**
     * Attempts to recover the existing AES Key or generates a new one if none is found.
     *
     * @return a valid  AES Key bytes
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     * @throws CryptoException             if the stored RSA keys can't be recovered and should be deemed invalid
     */
    @VisibleForTesting
    byte[] getAESKey() throws IncompatibleDeviceException, CryptoException {
        return getAESKey(KEY_ALIAS);
    }

    /**
     * Attempts to recover the existing AES Key or generates a new one if none is found.
     *
     * @param keyAlias The lookup key
     * @return a valid  AES Key bytes
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     * @throws CryptoException             if the stored RSA keys can't be recovered and should be deemed invalid
     */
    @VisibleForTesting
    byte[] getAESKey(@NonNull String keyAlias) throws IncompatibleDeviceException, CryptoException {
        final String encodedEncryptedAES = storage.retrieveString(keyAlias);
        if (encodedEncryptedAES != null) {
            //Return existing key
            byte[] encryptedAES = Base64.decode(encodedEncryptedAES, Base64.DEFAULT);
            byte[] existingAES = RSADecrypt(encryptedAES);
            final int aesExpectedLengthInBytes = AES_KEY_SIZE / 8;
            //Prevent returning an 'Empty key' (invalid/corrupted) that was mistakenly saved
            if (existingAES != null && existingAES.length == aesExpectedLengthInBytes) {
                //Key exists and has the right size
                return existingAES;
            }
        }
        //Key doesn't exist. Generate new AES
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGen.init(AES_KEY_SIZE);
            byte[] aes = keyGen.generateKey().getEncoded();
            //Save encrypted encoded version
            byte[] encryptedAES = RSAEncrypt(aes);
            String encodedEncryptedAESText = new String(Base64.encode(encryptedAES, Base64.DEFAULT));
            storage.store(KEY_ALIAS, encodedEncryptedAESText);
            return aes;
        } catch (NoSuchAlgorithmException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchAlgorithmException:
             *      Thrown if the Algorithm implementation is not available. AES was introduced in API 1
             *
             * Read more in https://developer.android.com/reference/javax/crypto/KeyGenerator
             */
            Log.e(TAG, "Error while creating the AES key.", e);
            throw new IncompatibleDeviceException(e);
        }
    }


    /**
     * Encrypts the given input bytes using a symmetric key (AES).
     * The AES key is stored protected by an asymmetric key pair (RSA).
     *
     * @param encryptedInput the input bytes to decrypt. There's no limit in size.
     * @return the decrypted output bytes
     * @throws CryptoException             if the RSA Key pair was deemed invalid and got deleted. Operation can be retried.
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    public byte[] decrypt(byte[] encryptedInput) throws CryptoException, IncompatibleDeviceException {
        try {
            final boolean hasLegacyEntry = keyStoreUtil.hasLegacyCredential()
                && !TextUtils.isEmpty(storage.retrieveString(keyStoreUtil.legacyKeyIVAlias()));
            final String keyAlias;
            final String keyIVAlias;
            if (hasLegacyEntry) {
                keyAlias = keyStoreUtil.legacyKeyAlias();
                keyIVAlias = keyStoreUtil.legacyKeyIVAlias();
            } else {
                keyAlias = KEY_ALIAS;
                keyIVAlias = KEY_IV_ALIAS;
            }
            SecretKey key = new SecretKeySpec(getAESKey(keyAlias), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            String encodedIV = storage.retrieveString(keyIVAlias);

            if (TextUtils.isEmpty(encodedIV)) {
                //AES key was JUST generated. If anything existed before, should be encrypted again first.
                throw new CryptoException("The encryption keys changed recently. You need to re-encrypt something first.", null);
            }
            byte[] iv = Base64.decode(encodedIV, Base64.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] output = cipher.doFinal(encryptedInput);

            if (hasLegacyEntry) {
                // first we must delete the keys since we have successfully decrypted the data
                // using the legacy key alias
                deleteAESKeys();
                deleteRSAKeys();

                // Now we must e-encrypt with the new key alias pattern. Since we deleted the
                // legacy keys from storage and the keystore, we should only hit this path once
                throw new NeedsMigrationException(output);
            }

            return output;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if NOPADDING is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             * - InvalidAlgorithmParameterException:
             *      If the IV parameter is null.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "Error while decrypting the input.", e);
            throw new IncompatibleDeviceException(e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            /*
             * Any of this exceptions mean the encrypted input is somehow corrupted and cannot be recovered.
             * - BadPaddingException:
             *      Thrown if the input doesn't contain the proper padding bytes. In this case, if the input contains padding.
             * - IllegalBlockSizeException:
             *      Thrown only on encrypt mode.
             */
            throw new CryptoException("The AES encrypted input is corrupted and cannot be recovered. Please discard it.", e);
        }
    }

    /**
     * Encrypts the given input bytes using a symmetric key (AES).
     * The AES key is stored protected by an asymmetric key pair (RSA).
     *
     * @param decryptedInput the input bytes to encrypt. There's no limit in size.
     * @return the encrypted output bytes
     * @throws CryptoException             if the RSA Key pair was deemed invalid and got deleted. Operation can be retried.
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    public byte[] encrypt(byte[] decryptedInput) throws CryptoException, IncompatibleDeviceException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(decryptedInput);
            byte[] encodedIV = Base64.encode(cipher.getIV(), Base64.DEFAULT);
            //Save IV for Decrypt stage
            final String encodedIVString = new String(encodedIV);
            storage.store(KEY_IV_ALIAS, encodedIVString);
            return encrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if NOPADDING is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             * - InvalidAlgorithmParameterException:
             *      If the IV parameter is null.
             * - BadPaddingException:
             *      Thrown only on decrypt mode.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "Error while encrypting the input.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            /*
             * - IllegalBlockSizeException:
             *      Thrown if no padding has been requested and the length is not multiple of block size.
             * - BadPaddingException:
             *      Thrown only on decrypt mode.
             */
            throw new CryptoException("The AES decrypted input is invalid.", e);
        }
    }
}

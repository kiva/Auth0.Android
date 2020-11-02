package com.auth0.android.authentication.storage;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

@RequiresApi(api = Build.VERSION_CODES.KITKAT)
class KeyStoreUtil {
    private static final String TAG = KeyStoreUtil.class.getSimpleName();

    private static final int RSA_KEY_SIZE = 2048;
    private static final String ALGORITHM_RSA = "RSA";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private final String LEGACY_KEY_ALIAS;
    private final String LEGACY_KEY_IV_ALIAS;

    private final Context context;

    public KeyStoreUtil(@NonNull Context context, @NonNull String legacyKeyAlias) {
        this.context = context;
        this.LEGACY_KEY_ALIAS = legacyKeyAlias;
        this.LEGACY_KEY_IV_ALIAS = legacyKeyAlias + "_iv";
    }

    @NonNull
    public String legacyKeyAlias() {
        return this.LEGACY_KEY_ALIAS;
    }

    @NonNull
    public String legacyKeyIVAlias() {
        return this.LEGACY_KEY_IV_ALIAS;
    }

    public boolean hasLegacyCredential() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            return keyStore.containsAlias(LEGACY_KEY_ALIAS);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "hasLegacyCredentials: Failed to load the Android Keystore", e);
            return false;
        }
    }

    /**
     * Helper method compatible with older Android versions to load the Private Key Entry from
     * the KeyStore using the {@param #keyAlias}.
     *
     * @param keyStore the KeyStore instance. Must be initialized (loaded).
     * @param keyAlias the alias key used with storage
     * @return the key entry stored in the KeyStore or null if not present.
     * @throws KeyStoreException           if the keystore was not initialized.
     * @throws NoSuchAlgorithmException    if device is not compatible with RSA algorithm. RSA is available since API 18.
     * @throws UnrecoverableEntryException if key cannot be recovered. Probably because it was invalidated by a Lock Screen change.
     */
    public KeyStore.PrivateKeyEntry getKeyEntryCompat(@NonNull KeyStore keyStore, @NonNull String keyAlias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        Log.d("AUTH0_DEBUG", "getKeyEntryCompat " + keyAlias);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, null);
        }

        //Following code is for API 28+
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);

        if (privateKey == null) {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, null);
        }

        Certificate certificate = keyStore.getCertificate(keyAlias);
        if (certificate == null) {
            return null;
        }
        return new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate});
    }

    public void generateKeyStore(@NonNull String keyAlias) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 25);
        AlgorithmParameterSpec spec;
        X500Principal principal = new X500Principal("CN=Auth0.Android,O=Auth0");

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            spec = new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setCertificateSubject(principal)
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setKeySize(RSA_KEY_SIZE)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .build();
        } else {
            //Following code is for API 18-22
            //Generate new RSA KeyPair and save it on the KeyStore
            KeyPairGeneratorSpec.Builder specBuilder = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(keyAlias)
                    .setSubject(principal)
                    .setKeySize(RSA_KEY_SIZE)
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime());

            KeyguardManager kManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
                //The next call can return null when the LockScreen is not configured
                Intent authIntent = kManager.createConfirmDeviceCredentialIntent(null, null);
                boolean keyguardEnabled = kManager.isKeyguardSecure() && authIntent != null;
                if (keyguardEnabled) {
                    //If a ScreenLock is setup, protect this key pair.
                    specBuilder.setEncryptionRequired();
                }
            }
            spec = specBuilder.build();
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE);
        generator.initialize(spec);
        generator.generateKeyPair();
    }
}

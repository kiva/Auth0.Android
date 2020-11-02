package com.auth0.android.authentication.storage;

import android.content.Context;
import android.os.Build;
import androidx.annotation.RequiresApi;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.robolectric.annotation.Config;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;

/**
 * Tests migration from legacy key alias to new key alias pattern
 */
@RequiresApi(api = Build.VERSION_CODES.KITKAT)
@RunWith(PowerMockRunner.class)
@PrepareForTest({CryptoUtil.class, KeyStoreUtil.class, KeyGenerator.class, TextUtils.class, Build.VERSION.class, Base64.class, Cipher.class, Log.class})
@Config(sdk = 22)
class CryptoUtilLegacyTest {
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_RSA = "RSA";

    public CryptoUtilLegacyTest() {
        super();
    }


    @Rule
    public ExpectedException exception = ExpectedException.none();

    private Storage storage = PowerMockito.mock(Storage.class);
    private Cipher rsaCipher = PowerMockito.mock(Cipher.class);
    private Cipher aesCipher = PowerMockito.mock(Cipher.class);
    private KeyStore keyStore = PowerMockito.mock(KeyStore.class);
    private KeyPairGenerator keyPairGenerator = PowerMockito.mock(KeyPairGenerator.class);
    private KeyGenerator keyGenerator = PowerMockito.mock(KeyGenerator.class);

    private CryptoUtil cryptoUtil;

    private static final String APP_PACKAGE_NAME = "com.mycompany.myapp";
    private static final String BASE_ALIAS = "keyName";
    private static final String KEY_ALIAS = APP_PACKAGE_NAME + "." + BASE_ALIAS;
    private static final String LEGACY_KEY_ALIAS = BASE_ALIAS;
    private Context context;

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Log.class);
        PowerMockito.mockStatic(TextUtils.class);
        PowerMockito.when(TextUtils.isEmpty(anyString())).then(new Answer<Boolean>() {
            @Override
            public Boolean answer(InvocationOnMock invocation) {
                String input = invocation.getArgumentAt(0, String.class);
                return input == null || input.isEmpty();
            }
        });

        context = mock(Context.class);
        when(context.getPackageName()).thenReturn(APP_PACKAGE_NAME);
        cryptoUtil = newCryptoUtilSpy();
    }

    // should remove legacy key aliases

    @Test
    public void testKeyAliasMigration() throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, KeyStoreException {
        ArgumentCaptor<SecretKey> secretKeyCaptor = ArgumentCaptor.forClass(SecretKey.class);
        ArgumentCaptor<IvParameterSpec> ivParameterSpecCaptor = ArgumentCaptor.forClass(IvParameterSpec.class);
        byte[] aesKey = "aes-decrypted-key".getBytes();
        byte[] data = "data".getBytes();
        byte[] decryptedData = new byte[]{0, 1, 2, 3, 4, 5};
        byte[] encryptedData = new byte[]{0, 1, 2, 3, 4, 5};
        String encodedIv = "iv-data";
        byte[] iv = new byte[]{99, 99, 11, 11};

        doReturn(aesKey).when(cryptoUtil).getAESKey(LEGACY_KEY_ALIAS);
        doReturn(decryptedData).when(aesCipher).doFinal(data);
        PowerMockito.when(aesCipher.doFinal(data)).thenReturn(decryptedData);
        doReturn(data).when(aesCipher).doFinal(decryptedData);
        PowerMockito.when(aesCipher.doFinal(decryptedData)).thenReturn(data);
        doReturn(encryptedData).when(aesCipher).doFinal(data);
        PowerMockito.when(aesCipher.doFinal(data)).thenReturn(encryptedData);
        PowerMockito.when(aesCipher.getIV()).thenReturn(iv);
        PowerMockito.when(keyStore.containsAlias(LEGACY_KEY_ALIAS)).thenReturn(true);
        PowerMockito.when(storage.retrieveString(LEGACY_KEY_ALIAS + "_iv")).thenReturn(encodedIv);
        PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(null);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.decode(encodedIv, Base64.DEFAULT)).thenReturn(encodedIv.getBytes());
        PowerMockito.when(Base64.encode(decryptedData, Base64.DEFAULT)).thenReturn("data".getBytes());
        PowerMockito.when(Base64.encode(iv, Base64.DEFAULT)).thenReturn(encodedIv.getBytes());


        SecretKey secretKey = PowerMockito.mock(SecretKey.class);
        PowerMockito.when(keyGenerator.generateKey()).thenReturn(secretKey);
        PowerMockito.when(secretKey.getEncoded()).thenReturn(decryptedData);
        doReturn(decryptedData).when(cryptoUtil).RSAEncrypt(decryptedData);

        final byte[] decrypted = cryptoUtil.decrypt(data);

        // validate decrypted data matches expected
        Mockito.verify(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyCaptor.capture(), ivParameterSpecCaptor.capture());
        assertThat(secretKeyCaptor.getValue(), is(notNullValue()));
        assertThat(secretKeyCaptor.getValue().getAlgorithm(), is(ALGORITHM_AES));
        assertThat(secretKeyCaptor.getValue().getEncoded(), is(aesKey));
        assertThat(ivParameterSpecCaptor.getValue(), is(notNullValue()));
        assertThat(ivParameterSpecCaptor.getValue().getIV(), is(encodedIv.getBytes()));

        // validate new key was generated
        assertThat(decrypted, is(decryptedData));
        Mockito.verify(keyGenerator).init(256);
        Mockito.verify(keyGenerator).generateKey();
        Mockito.verify(storage).store(KEY_ALIAS, "data");
        Mockito.verify(storage).store(KEY_ALIAS + "_iv", encodedIv);

        // validate old alias keys were removed
        Mockito.verify(storage).remove(LEGACY_KEY_ALIAS);
        Mockito.verify(storage).remove(LEGACY_KEY_ALIAS + "_iv");
    }

    private CryptoUtil newCryptoUtilSpy() throws Exception {
        CryptoUtil cryptoUtil = PowerMockito.spy(new CryptoUtil(context, storage, BASE_ALIAS));
        PowerMockito.mockStatic(KeyStore.class);
        PowerMockito.when(KeyStore.getInstance(ANDROID_KEY_STORE)).thenReturn(keyStore);
        PowerMockito.mockStatic(KeyPairGenerator.class);
        PowerMockito.when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE)).thenReturn(keyPairGenerator);
        PowerMockito.mockStatic(KeyGenerator.class);
        PowerMockito.when(KeyGenerator.getInstance(ALGORITHM_AES)).thenReturn(keyGenerator);
        PowerMockito.mockStatic(Cipher.class);
        PowerMockito.when(Cipher.getInstance(anyString())).then(new Answer<Cipher>() {
            @Override
            public Cipher answer(InvocationOnMock invocation) {
                String transformation = invocation.getArgumentAt(0, String.class);
                if (RSA_TRANSFORMATION.equals(transformation)) {
                    return rsaCipher;
                } else if (AES_TRANSFORMATION.equals(transformation)) {
                    return aesCipher;
                }
                return null;
            }
        });
        return cryptoUtil;
    }
}
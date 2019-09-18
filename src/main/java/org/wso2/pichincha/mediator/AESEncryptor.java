package org.wso2.pichincha.mediator;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptor {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String ENCODING = "UTF-8";
    private byte[] ivBytes;
    private SecretKey secretKey;

    public AESEncryptor(String key, String initialVectore) {

        setSecretKey(key);
        setIVBytes(initialVectore);
    }

    public String encrypt(String value) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {

        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

        byte[] encrypted = cipher.doFinal(value.getBytes(ENCODING));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String payload)
            throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException {

        byte[] encryptedTextBytes = Base64.getDecoder().decode(payload);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        return new String(decryptedTextBytes, ENCODING);
    }

    private void setIVBytes(String ivBytes) {

        this.ivBytes = Base64.getDecoder().decode(ivBytes);
    }

    private void setSecretKey(String secretKey) {

        this.secretKey = new SecretKeySpec(Base64.getDecoder().decode(secretKey), ALGORITHM);
    }
}

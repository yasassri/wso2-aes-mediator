package org.wso2.pichincha.mediator;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;

public class EncryptorMain {

    public static void main(String[] args) throws BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, DecoderException, InvalidAlgorithmParameterException {
            AESEncryptor aes = new AESEncryptor("Roqz+kzNHvp0GcYzd0u7sZh6a7QQgP+d2JKRUg0FJE8=" , "KTMDshf5SAfL6Utdr4p/9w==");
            String payload = "bAfNDXadnEITZ3oTrTSQzQ==";
            System.out.println("Decrypting "+ aes.decrypt(payload));
            System.out.println("Encrypting "+ aes.encrypt("Pichincha1"));

    }

}

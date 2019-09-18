package org.wso2.pichincha.mediator;

import java.util.Objects;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

/**
 * Performs AES Encryption/Decryption based on given values.
 */
public class AESEncryptMediator extends AbstractMediator {

    private static final String AES_PAYLOAD_PROP_NAME = "AES_PAYLOAD";
    private static final String AES_RESULT_PROP_NAME = "AES_RESULTS";
    private static final String AES_KEY_PROP_NAME = "AES_KEY";
    private static final String AES_IV_PROP_NAME = "AES_IV";
    private static final String AES_ACTION_PROP_NAME = "AES_ACTION"; // Action can be ENCRYPT or DECRYPT

    private static final String AES_ENCRYPT_ACTION_NAME = "ENCRYPT";
    private static final String AES_DECRYPT_ACTION_NAME = "DECRYPT";

    public boolean mediate(MessageContext context) {
        String payload = getPayload(context);
        String key = getSecretKey(context);
        String iv = getIVString(context);
        String action = getAction(context);
        if (isNullOrEmpty(payload)) {
            String error = "Property " + AES_PAYLOAD_PROP_NAME + " is null or empty.";
            log.error(error);
            context.setProperty("ERROR_MESSAGE",  error);
        } else if (isNullOrEmpty(key)) {
            completeProcess("Property " + AES_KEY_PROP_NAME + " is null or empty.", context);
        } else if (isNullOrEmpty(iv)) {
            completeProcess("Property " + AES_IV_PROP_NAME + " is null or empty.", context);
        } else if (isNullOrEmpty(action)) {
            completeProcess("Property " + AES_ACTION_PROP_NAME + " is null or empty.", context);
        }
        process(context, payload, key, iv, action);
        return true;
    }

    private boolean process(MessageContext ctx, String payload, String key, String iv, String action) {

        try {
            AESEncryptor encryptor = new AESEncryptor(key, iv);

            if (action.toUpperCase().equals(AES_ENCRYPT_ACTION_NAME)) {
                setResultPayload(ctx, encryptor.encrypt(payload));

            } else if (action.toUpperCase().equals(AES_DECRYPT_ACTION_NAME)) {
                System.out.println("In the Decrypto....");
                setResultPayload(ctx, encryptor.decrypt(payload));
            }
        } catch (Exception e) {
            handleCryptoError("Error while Encrypting/Decrypting the payload.", e, ctx);
        }
        return true;
    }

    private boolean isNullOrEmpty(String str) {

        if (str == null || str.isEmpty()) {
            return true;
        }
        return false;
    }

    private void completeProcess(String msg, MessageContext context) {
        context.setProperty("ERROR_MESSAGE", msg);
        // If the mandatory properties are not set we do not want to continue the flow.
        handleException(msg, context);
    }

    private void handleCryptoError(String msg, Exception e, MessageContext context) {
        log.error(msg);
        context.setProperty("ERROR_MESSAGE", e.getMessage());
    }

    private String getPayload(MessageContext context) {

        return Objects.toString(context.getProperty(AES_PAYLOAD_PROP_NAME), "");
    }

    private String getAction(MessageContext context) {

        return Objects.toString(context.getProperty(AES_ACTION_PROP_NAME), "");
    }

    private String getSecretKey(MessageContext context) {

        return Objects.toString(context.getProperty(AES_KEY_PROP_NAME), "");
    }

    private String getIVString(MessageContext context) {

        return Objects.toString(context.getProperty(AES_IV_PROP_NAME), "");
    }

    private void setResultPayload(MessageContext context, String respondPayload) {

        context.setProperty(AES_RESULT_PROP_NAME, respondPayload);
    }
}

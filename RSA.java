import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;

public class RSA
{
    public static KeyPair keyPair;
    
    public static String encrypt(PublicKey publicKey, String message) throws NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(PrivateKey privateKey, String encryptedMessage) throws NoSuchAlgorithmException,
     NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedMessage);
    }

    public static KeyPair makeKeyPair() throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.genKeyPair();
        return keyPair;
    }

    public static PublicKey getPublicKey()
    {
        return keyPair.getPublic();
    }
}


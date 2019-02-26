import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;
import java.util.Base64;
import java.io.*;
import java.nio.*;
import java.security.spec.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Mac;

public class Alice
{
    private static boolean doingAES = false;
    private static boolean doingHMAC = true;

    public static void writeToFile(String fileName, String data) throws IOException
    {
        BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
        writer.write(data);
        writer.close();
    }

    public static String readFromFile(String fileName) throws FileNotFoundException, IOException
    { 
        File file = new File(fileName);
        BufferedReader reader = new BufferedReader(new FileReader(file));

        String data = "";
        String inp;
        while ((inp = reader.readLine()) != null)
        {
            data += inp;
        }

        reader.close();
        return data;
    }

    public static PublicKey readPublicKeyFromFile(String fileName) throws FileNotFoundException, IOException,
    NoSuchAlgorithmException, InvalidKeySpecException
    {
    	File filePublicKey = new File("public.key");
   		FileInputStream fis = new FileInputStream("public.key");
    	byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
    	fis.read(encodedPublicKey);
    	fis.close();
    	
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
    			encodedPublicKey);
    	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    	return publicKey;
    }

    public static PublicKey generatePublicKey(byte[] pubKey)
    {
        PublicKey public_key = null;
        try 
        {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey);
            public_key = kf.generatePublic(keySpec);
        } 
        catch(NoSuchAlgorithmException e) 
        {
            System.out.println("Could not reconstruct the public key, the given algorithm oculd not be found.");
        } 
        catch(InvalidKeySpecException e) 
        {
            System.out.println("Could not reconstruct the public key");
    }

    return public_key;
    }

    public static void hashAndMessageToFile(String message) throws IOException, NoSuchAlgorithmException,
    InvalidKeyException
    {
        String secretKey = "2973279655720806";
        writeToFile("secretKey.txt", secretKey);

        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec sk = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        sha256_HMAC.init(sk);

        String HMAC = Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(message.getBytes()));

        BufferedWriter writer = new BufferedWriter(new FileWriter("hmac.txt"));
        writer.write(HMAC + "\n" + message);
        writer.close();
    }

    public static void main(String[] args) throws FileNotFoundException, IOException,
     NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
     BadPaddingException, InvalidKeySpecException
    {
        String toEncrypt = "";
        for (int i = 0; i < args.length; i++)
        {
            toEncrypt += args[i] + " ";
        }
        toEncrypt = toEncrypt.substring(0, toEncrypt.length() - 1);

        //AES Encryption
        if (doingAES)
        {
            AES aes = new AES();

            System.out.println("original message:  " + toEncrypt);

            final double startTime = System.currentTimeMillis();
            String encryptedString = "";
            for (int i = 0; i < 100; i++)
            {
                encryptedString = AES.encrypt(toEncrypt);
            }
            final double endTime = System.currentTimeMillis();
            System.out.println("Average AES encryption time: " + (endTime - startTime) / 100.0 + " ms");
            
            System.out.println("encrypted message: " + encryptedString);
            writeToFile("ctext.txt", encryptedString);
        }
        //RSA Encryption
        else if (!doingHMAC)
        {
            //byte[] bobKeyBytes = readPublicKeyFromFile("bobKey");
            //PublicKey bobKey = generatePublicKey(bobKeyBytes);
            PublicKey bobKey = readPublicKeyFromFile("bobPub.key");

            
            final double startTime = System.currentTimeMillis();
            String encryptedMessage = "";
            for (int i = 0; i < 100; i++)
            {
                encryptedMessage = RSA.encrypt(bobKey, toEncrypt);
            }
            final double endTime = System.currentTimeMillis();
            System.out.println("Average RSA encryption time: " + (endTime - startTime) / 100.0 + " ms");

            writeToFile("ctext.txt", encryptedMessage);
        }
        else
        {
            hashAndMessageToFile(toEncrypt);
        }
    }
}
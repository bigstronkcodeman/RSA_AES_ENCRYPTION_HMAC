import java.security.*;
import java.security.spec.*;
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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Mac;

public class Bob
{
    private static boolean doingAES = false;
    private static boolean doingHMAC = true;
    private static boolean decryptingRSA = false;
//    private static boolean decryptingRSA = false;
    private static boolean makeKey = false;

    public static void writeToFile(String fileName, String data) throws IOException
    {
        BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
        writer.write(data);
        writer.close();
    }

    public static void writePublicKeyToFile(String fileName, PublicKey publicKey) throws IOException, FileNotFoundException
    {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();
    }

    public static String readFromFile(String fileName) throws FileNotFoundException, IOException
    {
        File file = new File(fileName);
        BufferedReader reader = new BufferedReader(new FileReader(file));

        String encryptedData = "";
        String inp;
        while ((inp = reader.readLine()) != null)
        {
            encryptedData += inp;
        }

        reader.close();
        if (fileName == "ctext.txt")
        {
        	
        }
        return encryptedData;
    }
    
    public static void writeKeyPairToFiles(KeyPair kp) throws FileNotFoundException, IOException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
    BadPaddingException
    {
    	PrivateKey privateKey = kp.getPrivate();
		PublicKey publicKey = kp.getPublic();
 
		// Store Public Key
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream("public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream("private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
    }
    
    public static KeyPair getKeyPairFromFiles() throws IOException, NoSuchAlgorithmException,
	InvalidKeySpecException
    {
    	// Read Public Key
    	File filePublicKey = new File("public.key");
   		FileInputStream fis = new FileInputStream("public.key");
    	byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
    	fis.read(encodedPublicKey);
    	fis.close();
     
    	// Read Private Key
    	File filePrivateKey = new File("private.key");
    	fis = new FileInputStream("private.key");
    	byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
    	fis.read(encodedPrivateKey);
    	fis.close();
     
    	// Generate KeyPair
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
    			encodedPublicKey);
    	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
     
    	PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
    			encodedPrivateKey);
    	PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
     
    	return new KeyPair(publicKey, privateKey);
    }

    public static String[] read_2LinesFromFile(String fileName) throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        String hmac = "";
        String message = "";
        String line = "";
        int currentLine = 1;
        while ((line = br.readLine()) != null)
        {
            switch (currentLine)
            {
                case 1:
                    hmac = line;
                    break;
                case 2:
                    message = line;
                    break;
            }
            currentLine++;
        }
        String[] contents = new String[2];
        contents[0] = hmac;
        contents[1] = message;
        return contents;
    }

    public static boolean verifyHmac(String fileName) throws IOException, NoSuchAlgorithmException,
    InvalidKeyException
    {
        String[] hmacContents = read_2LinesFromFile("hmac.txt");
        String HMAC = hmacContents[0];
        String message = hmacContents[1];

        String sk = readFromFile("secretKey.txt");
        SecretKeySpec secretKey = new SecretKeySpec(sk.getBytes(), "HmacSHA256");

        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        sha256_HMAC.init(secretKey);
        String hmacFromText = Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(message.getBytes()));
        return HMAC.equals(hmacFromText);
    }

    public static void main(String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
    BadPaddingException, InvalidKeySpecException
    {
        //AES ENCRYPTION
        if (doingAES)
        {
            AES aes = new AES();

            String encryptedString = readFromFile("ctext.txt");
            System.out.println("encrypted message: " + encryptedString);

            final double startTime = System.currentTimeMillis();
            String decryptedString = "";
            for (int i = 0; i < 100; i++)
            {
                decryptedString = AES.decrypt(encryptedString);
            }
            final double endTime = System.currentTimeMillis();
            System.out.println("Average AES decryption time: " + (endTime - startTime) / 100.0 + " ms");

            System.out.println("decrypted message: " + decryptedString);
        }
        //RSA ENCRYPTION
        else if (!doingHMAC)
        {
        	KeyPair myKeys;
        	if (makeKey)
        	{
        		myKeys = RSA.makeKeyPair();
        		writeKeyPairToFiles(myKeys);
        	}
        	else
        	{
        		myKeys = getKeyPairFromFiles();
        	}
        	//PublicKey publicKey = myKeys.getPublic();
        	PrivateKey privateKey = myKeys.getPrivate();
            if (decryptingRSA)
            {
                String encryptedString = readFromFile("ctext.txt");
                System.out.println("encrypted message: " + encryptedString);

                final double startTime = System.currentTimeMillis();
                String decryptedString = "";
                for (int i = 0; i < 100; i++)
                {
                    decryptedString = RSA.decrypt(privateKey, encryptedString);
                }
                final double endTime = System.currentTimeMillis();
                System.out.println("Average RSA decryption time: " + (endTime - startTime) / 100.0 + " ms");

                System.out.println("decrypted message: " + decryptedString);
            }
            else
            {
                //writePublicKeyToFile("bobPub.key", publicKey);
            }
        }
        else
        {
            if (verifyHmac("hmac.txt"))
            {
                System.out.println("Verification successful");
            }
            else
            {
                System.out.println("Verification not successful");
            }
        }
    }
}
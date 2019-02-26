import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;
import java.io.*;

public class AES 
{
    private static String key;
    private static final String initVector = "encryptionIntVec";

    AES() throws FileNotFoundException, IOException
    {
        File file = new File("key.txt");
        BufferedReader reader = new BufferedReader(new FileReader(file));

        key = "";
        String str;
        try 
        {
            while ((str = reader.readLine()) != null)
            {
                key += str;
            }
        }
        catch (IOException ex)
        {
            ex.printStackTrace();
        }
        key = key.substring(0, 16);
    }

    public static String encrypt(String value) 
    {
        try 
        {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
    
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
    
            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        }
        catch (Exception ex) 
        {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encrypted) 
    {
        try 
        {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
    
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
    
            return new String(original);
        } 
        catch (Exception ex) 
        {
            ex.printStackTrace();
        }
    
        return null;
    }
}
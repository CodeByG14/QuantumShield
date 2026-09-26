import java.security.*;
import javax.crypto.*;

public class CryptoDemo {
    public static void main(String[] args) throws Exception {
        // RSA key generation (Shor-vulnerable)
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        
        // SHA-1 hashing (Grover-affected)
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hash1 = sha1.digest("test data".getBytes());
        
        // SHA-256 hashing (Grover-affected)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash256 = sha256.digest("test data".getBytes());
        
        // AES encryption (default 128-bit, Grover-affected)
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128);
        SecretKey aesKey = aesGen.generateKey();
        
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        
        System.out.println("Crypto operations configured");
    }
}

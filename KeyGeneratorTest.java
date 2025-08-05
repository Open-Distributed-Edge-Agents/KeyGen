import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class KeyGeneratorTest {

    // Serialize public key to Base64 string
    public static String serializePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    // Serialize private key to Base64 string
    public static String serializePrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    // Deserialize public key from Base64 string
    public static PublicKey deserializePublicKey(String publicKeyStr) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    // Deserialize private key from Base64 string
    public static PrivateKey deserializePrivateKey(String privateKeyStr) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        // Serialize to strings
        String pubStr = serializePublicKey(pair.getPublic());
        String privStr = serializePrivateKey(pair.getPrivate());

        // Deserialize from strings
        PublicKey pubDeserialized = deserializePublicKey(pubStr);
        PrivateKey privDeserialized = deserializePrivateKey(privStr);

        // Test: Encrypt with public, decrypt with private
        String message = "Hello, world!";
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, pubDeserialized);
        byte[] encrypted = encryptCipher.doFinal(message.getBytes());

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privDeserialized);
        byte[] decrypted = decryptCipher.doFinal(encrypted);

        String decryptedMessage = new String(decrypted);

        if (message.equals(decryptedMessage)) {
            System.out.println("Test passed: Key serialization/deserialization works.");
        } else {
            System.out.println("Test failed: Decrypted message does not match original.");
        }
    }
}
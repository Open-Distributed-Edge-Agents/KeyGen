import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyGenerator {
    public static String serializePublicKey(PublicKey publicKey) {
        // Encode the public key in X.509 format (DER encoded) and then Base64 encode
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static String serializePrivateKey(PrivateKey privateKey) {
        // Encode the private key in PKCS#8 format (DER encoded) and then Base64 encode
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        // Serialize keys
        String publicKeyStr = serializePublicKey(pair.getPublic());
        String privateKeyStr = serializePrivateKey(pair.getPrivate());

        // Print serialized keys
        System.out.println("Public Key (Base64):");
        System.out.println(publicKeyStr);
        System.out.println("\nPrivate Key (Base64):");
        System.out.println(privateKeyStr);
    }
}

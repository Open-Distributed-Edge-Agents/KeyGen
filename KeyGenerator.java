import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.io.FileOutputStream;
import java.io.IOException;

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
        if (args.length < 1) {
            System.err.println("Usage: java KeyGenerator <name>");
            System.exit(1);
        }
        String name = args[0];

        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        // Serialize keys
        String publicKeyStr = serializePublicKey(pair.getPublic());
        String privateKeyStr = serializePrivateKey(pair.getPrivate());

        // Save keys to files
        writeToFile(name + ".pub", publicKeyStr);
        writeToFile(name + ".key", privateKeyStr);

        System.out.println("Keys saved as " + name + ".pub and " + name + ".key");
    }

    private static void writeToFile(String filename, String content) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(content.getBytes());
        }
    }
}

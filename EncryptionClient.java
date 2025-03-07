import java.io.*;
import java.net.*;
import javax.crypto.*;

import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class EncryptionClient {

    private static final String AES_ALGORITHM = "AES";
    private static final String DES_ALGORITHM = "DES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final int RSA_KEY_SIZE = 2048;

    // AES key generation
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(128);
        return keyGen.generateKey();
    }

    // DES key generation
    public static SecretKey generateDESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(DES_ALGORITHM);
        keyGen.init(56);
        return keyGen.generateKey();
    }

    // RSA key pair generation
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(RSA_KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    // AES Encryption
    public static String encryptAES(String plainText, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // DES Encryption
    public static String encryptDES(String aesEncryptedText, SecretKey desKey) throws Exception {
        Cipher cipher = Cipher.getInstance(DES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] encryptedBytes = cipher.doFinal(aesEncryptedText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // RSA Encryption
    public static String encryptKeyRSA(SecretKey key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(key.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) throws Exception {

        System.out.println("Enter the plaintext: ");
        Scanner sc = new Scanner(System.in);
        String plainText = sc.nextLine();

        // Generate AES, DES, and RSA keys
        SecretKey aesKey = generateAESKey();
        SecretKey desKey = generateDESKey();
        KeyPair rsaKeyPair = generateRSAKeyPair();

        // Encrypt data
        String aesEncrypted = encryptAES(plainText, aesKey);
        String desEncrypted = encryptDES(aesEncrypted, desKey);

        // Encrypt AES and DES keys with RSA
        String encryptedAESKey = encryptKeyRSA(aesKey, rsaKeyPair.getPublic());
        String encryptedDESKey = encryptKeyRSA(desKey, rsaKeyPair.getPublic());

        // Output encrypted data and keys
        System.out.println();
        System.out.println("\n plainText: " + plainText);
        System.out.println("\n Encrypted Data: " + desEncrypted);
        System.out.println("\n Encrypted AES Key: " + encryptedAESKey);
        System.out.println("\n Encrypted DES Key: " + encryptedDESKey);

        // Convert RSA private key to Base64 for sending to the server
        String rsaPrivateKeyBase64 = Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded());

        // Connect to the server
        Socket socket = new Socket("localhost", 12345); // Server address and port
        ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());

        // Send encrypted data, keys, and private key to the server
        outputStream.writeObject(desEncrypted);
        outputStream.writeObject(encryptedAESKey);
        outputStream.writeObject(encryptedDESKey);
        outputStream.writeObject(rsaPrivateKeyBase64);

        // Close the connection
        outputStream.close();
        socket.close();
        sc.close();
    }
}

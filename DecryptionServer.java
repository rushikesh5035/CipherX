import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class DecryptionServer {

    private static final String AES_ALGORITHM = "AES";
    private static final String DES_ALGORITHM = "DES";
    private static final String RSA_ALGORITHM = "RSA";

    // RSA Decryption
    public static SecretKey decryptKeyRSA(String encryptedKey, PrivateKey privateKey, String algorithm)
            throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedKey);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new SecretKeySpec(decryptedBytes, algorithm);
    }

    // DES Decryption
    public static String decryptDES(String encryptedText, SecretKey desKey) throws Exception {
        Cipher cipher = Cipher.getInstance(DES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, desKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // AES Decryption
    public static String decryptAES(String encryptedText, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // Convert Base64 to PrivateKey
    public static PrivateKey getPrivateKeyFromBase64(String base64PrivateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    public static void main(String[] args) {
        int port = 12345;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("\n Server is listening on port " + port);

            while (true) {
                try (Socket socket = serverSocket.accept();
                        ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream())) {

                    System.out.println("\n Client connected");

                    // Receive encrypted data, keys, and RSA private key
                    String encryptedData = (String) inputStream.readObject();
                    String encryptedAESKey = (String) inputStream.readObject();
                    String encryptedDESKey = (String) inputStream.readObject();
                    String rsaPrivateKeyBase64 = (String) inputStream.readObject();

                    // Get RSA Private Key
                    PrivateKey privateKey = getPrivateKeyFromBase64(rsaPrivateKeyBase64);

                    // Decrypt AES and DES keys
                    SecretKey aesKey = decryptKeyRSA(encryptedAESKey, privateKey, AES_ALGORITHM);
                    SecretKey desKey = decryptKeyRSA(encryptedDESKey, privateKey, DES_ALGORITHM);

                    // Decrypt the data
                    String desDecrypted = decryptDES(encryptedData, desKey);
                    String aesDecrypted = decryptAES(desDecrypted, aesKey);

                    // Print the decrypted message
                    System.out.println("\n Decrypted Data: " + aesDecrypted);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        } catch (IOException e) {
            System.err.println("Port " + port + " is already in use. Try a different port.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

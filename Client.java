import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class Client {

    private static String PRIVATE_KEY_FILE = "";
    private static final String SERVER_PUBLIC_KEY_FILE = "./server.pub";

    public static void main(String[] args) {
        Path clientFilePath = Paths.get("./" + args[2] + ".pub");
        if (args.length != 3) {
            System.out.println("Usage: java Client host port userid");
            return;
        } else if (!Files.exists(clientFilePath)) {
            System.out.println("ERROR: User not found.");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2].toLowerCase();

        try {
            Socket socket = new Socket(host, port);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            String hashedUserId = hashUserId(userid);
            out.writeObject(hashedUserId);

            int numMessages = (int) in.readObject();
            System.out.println(numMessages + " new message(s) for you.");

            for (int i = 0; i < numMessages; i++) {
                byte[] encryptedMessage = (byte[]) in.readObject();
                byte[] signature = (byte[]) in.readObject();

                if (verifySignature(encryptedMessage, signature)) {
                    String decryptedMessage = decryptMessage(encryptedMessage, userid);
                    String[] parts = decryptedMessage.split(":");
                    String message = parts[1];
                    System.out.println("Message: " + message);

                } else {
                    System.out.println("ERROR: Signature could not be verified. Discarding message.");
                    socket.close();
                }
            }

            System.out.println("Do you want to send a message? [y/n]");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String choice = reader.readLine();
            if (choice.equalsIgnoreCase("y")) {
                System.out.println("Enter the recipient userid:");
                String recipient = reader.readLine().toLowerCase();
                Path recipientFilePath = Paths.get("./" + recipient + ".pub");
                // If recipient userid doesn't exist
                if (!Files.exists(recipientFilePath)) {
                    System.out.println("ERROR: Recipient not found.");
                    out.writeObject("no_recipient");
                    return;
                }

                PRIVATE_KEY_FILE = "./" + userid + ".prv";
                System.out.println("Enter your message:");
                String message = reader.readLine();

                long timestamp = System.currentTimeMillis();
                byte[] encryptedMessage = encryptMessage(recipient + ":" + message);
                byte[] timestampBytes = longToBytes(timestamp);

                byte[] combined = new byte[timestampBytes.length + encryptedMessage.length];
                System.arraycopy(timestampBytes, 0, combined, 0, timestampBytes.length);
                System.arraycopy(encryptedMessage, 0, combined, timestampBytes.length, encryptedMessage.length);

                byte[] signature = generateSignature(combined);
                out.writeObject(encryptedMessage);
                out.writeObject(timestamp);
                out.writeObject(signature);
                out.writeObject(userid);

            } else {
                // Tell the server that the user chose not to send a message
                out.writeObject("no_message");
            }
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String hashUserId(String userid) throws NoSuchAlgorithmException {
        String secret = "gfhk2024:";
        String secretUserid = secret + userid;
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] hashedBytes = messageDigest.digest(secretUserid.getBytes());
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : hashedBytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    private static byte[] encryptMessage(String message) throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(SERVER_PUBLIC_KEY_FILE));
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    private static String decryptMessage(byte[] encryptedMessage, String userid) throws Exception {
        PRIVATE_KEY_FILE = "./" + userid + ".prv";
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }


    private static byte[] generateSignature(byte[] data) throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signature) throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(SERVER_PUBLIC_KEY_FILE));
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);

        Signature signature2 = Signature.getInstance("SHA256withRSA");
        signature2.initVerify(publicKey);
        signature2.update(data);
        return signature2.verify(signature);
    }

    public static byte[] longToBytes(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(value);
        return buffer.array();
    }
}

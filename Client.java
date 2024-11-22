import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.text.SimpleDateFormat;
import java.util.Date;
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
        String userid = args[2];

        try {
            Socket socket = new Socket(host, port);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            String hashedUserId = hashUserId(userid);
            out.writeObject(hashedUserId);

            int numMessages = (int) in.readObject();
            System.out.println(numMessages + " new message(s) for you.");

            for (int i = 0; i < numMessages; i++) {
                // long timestamp = System.currentTimeMillis();
                byte[] encryptedMessage = (byte[]) in.readObject();
                byte[] signature = (byte[]) in.readObject();
                // byte[] timestampBytes = longToBytes(timestamp);

//                byte[] combined = new byte[timestampBytes.length + encryptedMessage.length];
//                System.arraycopy(timestampBytes, 0, combined, 0, timestampBytes.length);
//                System.arraycopy(encryptedMessage, 0, combined, timestampBytes.length, encryptedMessage.length);

                if (verifySignature(encryptedMessage, signature)) {
                    String decryptedMessage = decryptMessage(encryptedMessage, userid);
                    String[] parts = decryptedMessage.split(":");
                    String message = parts[1];
                    Long timestamp = (long) in.readObject();
                    Date date = new Date(timestamp);
                    SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                    String formattedDate = sdf.format(date);
                    System.out.println("Date: " + formattedDate);
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
                String recipient = reader.readLine();
                Path recipientFilePath = Paths.get("./" + recipient + ".pub");
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
        String input = secret + userid;
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashedBytes = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashedBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] encryptMessage(String message) throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(SERVER_PUBLIC_KEY_FILE));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    private static String decryptMessage(byte[] encryptedMessage, String userid) throws Exception {
        PRIVATE_KEY_FILE = "./" + userid + ".prv";
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    public static byte[] longToBytes(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(value);
        return buffer.array();
    }

    private static byte[] generateSignature(byte[] data) throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signature) throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(SERVER_PUBLIC_KEY_FILE));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
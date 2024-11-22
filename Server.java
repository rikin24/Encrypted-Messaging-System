import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.crypto.*;

public class Server {

    private static final String PRIVATE_KEY_FILE = "./server.prv";
    private static String SENDER_PUBLIC_KEY_FILE = "";
    private static String RECIPIENT_PUBLIC_KEY_FILE = "";
    private static final Map<String, TreeMap<Long, byte[]>> messagesMap = new HashMap<>();

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Server port");
            return;
        }

        int port = Integer.parseInt(args[0]);

        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server listening on port " + port + "...");

            while (true) {

                Socket socket = serverSocket.accept();

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                // Read hashedUserId from client
                String hashedUserId = (String) in.readObject();
                System.out.println("user " + hashedUserId + " has logged in");

                // Retrieve messages for the user
                Map<Long, byte[]> userMap = messagesMap.getOrDefault(hashedUserId, new Map<Long, byte[]>);

                out.writeObject(userMap.size());

                for (Map.Entry<Long, byte[]> entry : userMap.entrySet()) {
                    long timestamp = entry.getKey();
                    byte[] message = entry.getValue();
                    byte[] signature = generateSignatureForMessage(timestamp, message);

                    out.writeObject(message);
                    out.writeObject(signature);
                    out.writeObject(timestamp);
                }
                messagesMap.remove(hashedUserId);
                int numMessages = messages.size();
                out.writeObject(numMessages);
                System.out.println("delivering " + numMessages + " message(s)...");

                Object data = in.readObject();
                // Check if user chooses to send a message
                if (data instanceof String && data.equals("no_message")) {
                    System.out.println("no incoming message.");
                } else if (data instanceof String && data.equals("no_recipient"))  {
                    System.out.println("ERROR: recipient not found.");
                } else if  (data instanceof byte[]) {
                    byte[] encryptedMessage = (byte[]) data;
                    Long timestamp = (Long) in.readObject();
                    byte[] timestampBytes = Client.longToBytes(timestamp);
                    byte[] signature = (byte[]) in.readObject();
                    String sender = (String) in.readObject();
                    byte[] combined = new byte[timestampBytes.length + encryptedMessage.length];
                    System.arraycopy(timestampBytes, 0, combined, 0, timestampBytes.length);
                    System.arraycopy(encryptedMessage, 0, combined, timestampBytes.length, encryptedMessage.length);
                    Date date = new Date(timestamp);
                    SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                    String formattedDate = sdf.format(date);
                    out.writeObject(timestamp);
                    SENDER_PUBLIC_KEY_FILE = "./" + sender + ".pub";
                    if (verifySignature(combined, signature)) {
                        String decryptedMessage = decryptMessage(encryptedMessage);
                        if (decryptedMessage != null) {
                            String[] parts = decryptedMessage.split(":");
                            if (parts.length >= 2) {
                                String message = parts[1];
                                RECIPIENT_PUBLIC_KEY_FILE = "./" + parts[0] + ".pub";
                                encryptedMessage = encryptMessage(parts[0] + ":" + message);
                                storeMessage(hashUserId(parts[0]), encryptedMessage);
                                System.out.println("incoming message from " + sender);
                                System.out.println("Date: " + formattedDate);
                                System.out.println("recipient: " + parts[0]);
                                System.out.println("message: " + message);
                            } else {
                                System.out.println("ERROR: Incorrect format.");
                            }
                        } else {
                            System.out.println("ERROR: Decryption failed.");
                        }
                    } else {
                        System.out.println("ERROR: Invalid message.");
                    }
                }
                else {
                    System.out.println("No new message from client.");
                }
                socket.close();
            }
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

    private static String decryptMessage(byte[] encryptedMessage) {
        try {
            if (encryptedMessage == null || encryptedMessage.length == 0) {
                System.out.println("ERROR: No encrypted message received.");
                return null;
            }

            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedMessage);

            String decryptedMessage = new String(decryptedBytes);
            return decryptedMessage;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void storeMessage(String hashedRecipient, byte[] encryptedMessage) {
        List<byte[]> recipientMessages = messagesMap.getOrDefault(hashedRecipient, new ArrayList<>());
        recipientMessages.add(encryptedMessage);
        messagesMap.put(hashedRecipient, recipientMessages);
    }

    private static boolean verifySignature(byte[] data, byte[] signature) throws Exception {

        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(SENDER_PUBLIC_KEY_FILE));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
    private static byte[] generateSignatureForMessage(Long timestamp, byte[] message) throws Exception {
        byte[] combined = new byte[timestamp, message];

        byte[] keyBytes = Files.readAllBytes(Paths.get("./Server.prv"));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(kf.generatePrivate(spec));
        privateSignature.update(message);
        return privateSignature.sign();
    }

    private static byte[] encryptMessage(String message) throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(RECIPIENT_PUBLIC_KEY_FILE));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }
}
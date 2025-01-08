# Encrypted Messaging System
A client-server system for securely exchanging messages between users, using RSA encryption, digital signatures, and hashing techniques. The system ensures 100% data confidentiality and message integrity, as well as certifying authentication integrity and ensuring zero risk of data persistence or long-term storage vulnerabilities, making it a secure solution for sensitive communications.

## Usage
1. Compile the Server, Client and RSAKeyGen java files into classes, using the **javac** command in terminal.
2. Generate server public and private keys, which should have the userid "server" by running the following command:
   ```
   java RSAKeyGen server
   ```
3. Create user keys by entering the same command with the relevant userid each time as shown:
   ```
   java RSAKeyGen <userid>
   ```
4. Run the server via the command ```java Server <port>```
5. Log in as a user: ```java Client <host> <port> <userid>
6. Follow the intuitive prompts once logged in to being messaging securely!

/* This program generates a pair of matching public/private RSA keys.
 * It takes a userid as an argument, and places the generated keys in
 * "<userid>.pub" and "<userid>.prv" in the current working directory.
 * It is up to you to put the generated keys at some appropriate
 * location for use.
 *
 * This file does not contain any code that you need to include in
 * your own program, and is not part of the submission.
 */

import java.io.*;
import java.security.*;

public class RSAKeyGen {

	public static void main(String [] args) throws Exception {

		if (args.length != 1) {
			System.err.println("Usage: java RSAKeyGen userid");
			System.exit(-1);
		}

		String userId = args[0].toLowerCase();

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();

		FileOutputStream fos = new FileOutputStream(userId + ".pub");
		fos.write(kp.getPublic().getEncoded());
		fos.close();

		fos = new FileOutputStream(userId + ".prv");
		fos.write(kp.getPrivate().getEncoded());
		fos.close();

	}

}

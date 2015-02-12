package network.security.common;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public class util {

	public static final int NONCE_SIZE = 16;	
	public static final int ITERATIONS = 10000;
	public static final int KEY_LENGTH = 256; // 32 bytes, hashed key
	public static final int RSA_KEY_LEN = 2048;
	public static final int HASHED_PWD_SIZE = 32; //32 bytes, i.e. 256 bits
	public static final int MAX_MSG = 65507;
	public static final int SALT_SIZE = 32;
	public static final int RSA_KEY_ENCODED_LEN = 294; //294 bytes after key.getEncoded();
	public static final int USERNAME_SIZE = 5; //5 bytes, i.e. 40 bits
	
	public static final String LOGIN_REQUEST = "LOGIN_REQUEST";
	public static final String LIST_REQUEST = "LIST_REQUEST";
	public static final String LOGOUT_REQUEST = "LOGOUT_REQUEST";
	public static final String TALK_REQUEST = "I WANT TO TALK TO ";
	
	
	public static final String NOT_ONLINE = "TARGET USER IS NOT ONLINE NOW";
	public static final String LOGOUT_SUCCEED = "LOGOUT SUCCEED";
	public static final String LOGOUT_FAIL = "LOGOUT FAIL";
	
	
	private static final Random random = new SecureRandom();
	private static final Logger log = Logger.getLogger(Thread.currentThread()
			.getStackTrace()[0].getClassName());



	static public byte[] getNextNonce() {
		byte[] nonce = new byte[NONCE_SIZE];
		random.nextBytes(nonce);
		return nonce;
	}

	public static byte[] getHashedPassword(byte[] salt, String password) {
		log.info("getHashedPassword: salt=" + salt + ", password=" + password);
		char[] pwd = cloneArrayAndEraseOriginal(password.toCharArray());
		KeySpec spec = new PBEKeySpec(pwd, salt, ITERATIONS, KEY_LENGTH);
		try {
			SecretKeyFactory f = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA1");
			return f.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new AssertionError("Error while hashing a password: "
					+ e.getMessage(), e);
		}

	}

	private static char[] cloneArrayAndEraseOriginal(char[] password) {
		char[] pwd = password.clone();
		Arrays.fill(password, Character.MIN_VALUE);
		return pwd;
	}

	public static PublicKey getPublicKey(String publicKey_file,
			KeyFactory rsaKeyFactory) throws Exception {
		byte[] keyByte = readByte(new File(publicKey_file));
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(keyByte);
		return rsaKeyFactory.generatePublic(publicSpec);
	}
	
	
	public static PrivateKey getPrivateKey(String privateKey_file, KeyFactory rsaKeyFactory) throws Exception {
		byte[] keyByte = readByte(new File(privateKey_file));
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(keyByte);	
		return rsaKeyFactory.generatePrivate(privateSpec);
	}

	public static byte[] readByte(File file) throws Exception {

		if (file.length() > Integer.MAX_VALUE)
			throw new Exception("File is too big");

		byte[] tempBytesForFile = new byte[(int) file.length()];
		InputStream inStream = new FileInputStream(file);
		DataInputStream dataStream = new DataInputStream(inStream);
		dataStream.readFully(tempBytesForFile);
		inStream.close();
		dataStream.close();

		return tempBytesForFile;

	}
	
	
	public static KeyPair generateKeyPair() throws Exception{
		log.info("Generating RSA key pair");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(RSA_KEY_LEN);
		KeyPair key = keyGen.generateKeyPair();		
		return key;			
	}
	
	
	
	/*
	 * Concatenate all the arrays to an array  
	 * 
	 * */
	public static  byte[] concatAll(byte[] first, byte[]... rest) {
		  int totalLength = first.length;
		  for (byte[] array : rest) {
		    totalLength += array.length;
		  }
		  byte[] result = Arrays.copyOf(first, totalLength);
		  int offset = first.length;
		  for (byte[] array : rest) {
		    System.arraycopy(array, 0, result, offset, array.length);
		    offset += array.length;
		  }
		  return result;
		}
	

	/*
	 * Generate a AES key
	 * */
	public static Key generateAESkey() throws Exception {
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		Key key = gen.generateKey();
		return key;
	}
	
	
	
	public static byte[] encryptMsgWithAES(Key aesKey, byte[] msg) throws Exception{
		Cipher secCipher;
		secCipher = Cipher.getInstance("AES");
		secCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		return secCipher.doFinal(msg);
	}
	
	
	
	
	public static byte[] decryptMsgWithAES(Key aesKey, byte[] msg) throws Exception {			
		Cipher secCipher;
		secCipher = Cipher.getInstance("AES");
		secCipher.init(Cipher.DECRYPT_MODE, aesKey);
		byte[] decryptedText = secCipher.doFinal(msg);
		return decryptedText;
	}
	
	
	
	public static byte[] encryptMsgWithPubKey(PublicKey pubKey, byte[] msg) throws Exception {
		Cipher publicCipher = Cipher.getInstance("RSA");
		publicCipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] enAuthMsg = publicCipher.doFinal(msg);
		return enAuthMsg;		
	}
	
	
	public static byte[] decryptMsgWithPrvKey(PrivateKey prvKey, byte[] msg) throws Exception {
		Cipher privateCipher = Cipher.getInstance("RSA");
		privateCipher.init(Cipher.DECRYPT_MODE, prvKey);
		byte[] enAuthMsg = privateCipher.doFinal(msg);
		return enAuthMsg;		
	}

	
	
	public static Key getAesKeyFromWrapped(byte[] aesKeyEncrypted, PrivateKey prvKey) throws Exception {
		Cipher privateCipher;
		privateCipher = Cipher.getInstance("RSA");
		privateCipher.init(Cipher.UNWRAP_MODE, prvKey);
		Key aesKey = privateCipher.unwrap(aesKeyEncrypted, "AES", Cipher.SECRET_KEY);
		return aesKey;
	}
	
	public static byte[] wrapAesKeyWithPubKey(Key aesKey, PublicKey pubKey) throws Exception{
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		Cipher publicCipher = Cipher.getInstance("RSA");
		publicCipher.init(Cipher.WRAP_MODE, pubKey);
		return publicCipher.wrap(aesKey);
	}
	
	
	public static PublicKey recoverPubKey(byte[] pubKeyBytes) throws Exception{
		log.info("Recovering public key from bytes..");
		PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKeyBytes));	
		return pubKey;
	}
	
}

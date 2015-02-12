package network.security.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import network.security.common.util;

public class init {

	private static final String pwdFile = "userPwd3";
	private static final int HASHED_PWD_SIZE = util.HASHED_PWD_SIZE; //32 bytes, i.e. 256 bits
	private static final String SERVER_PRIVATE_KEY_FILE = "server_private_key.der";
	
	public void start() throws Exception {
		loadUserInfo();
		loadServerPrivateKey();		
	}
	
	
	private void loadUserInfo() throws Exception {

		try {
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(pwdFile));
		    List<byte[]> byteList = (List<byte[]>) in.readObject();

			for (byte[] line : byteList) {
				insertToMap(line);
			}
			in.close();

		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(
					"Server failed to load the userPwd file for users' information.");

		}
	}
	
	private void insertToMap(byte[] line) throws Exception {
		
		
		byte[] hashedPwd = Arrays.copyOfRange(line, 0, HASHED_PWD_SIZE);
		byte[] uName = Arrays
				.copyOfRange(line, HASHED_PWD_SIZE, line.length);
		IMserver.pwdMap.put(new String(uName), hashedPwd);
	}
	
	
	private void loadServerPrivateKey() throws Exception {
		
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		IMserver.serverPrvKey = util.getPrivateKey(SERVER_PRIVATE_KEY_FILE,
				rsaKeyFactory);		
	}
}

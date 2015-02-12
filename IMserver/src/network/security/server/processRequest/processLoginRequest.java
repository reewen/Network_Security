package network.security.server.processRequest;

import java.net.InetAddress;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import network.security.server.IMserver;
import network.security.server.monitor;
import network.security.server.serverThread;
import network.security.common.util;

public class processLoginRequest {
	
	private final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	private static final Random random = new SecureRandom();
	private static final int NONCE_SIZE = util.NONCE_SIZE; //16 bytes.
	private serverThread sThread = null;
	
	
	
	private byte[] N1 = null;
	private byte[] N3 = null;
	
	private PublicKey clientPubKey = null;
	private Key sessionKey = null;
	private String userName = null;
	private byte[] srvPortClient = null;
	
	private final String LOGIN_FAIL = "SOMETHING ERROR DURING MUTUAL AUTHENTICATION";
	private final String CONNECT = "CONFIRM_CONNECTED";
	

	public void start(monitor mo,  InetAddress clientAddr, int port, serverThread st, String msg) throws Exception {
		// msg can be left out, because it is login
		log.info("Processing login request from thread " + clientAddr);
		sThread = mo.findClient(clientAddr, port);
		if (sThread != null) {

			mutualAuthentication();

			mo.insertClient(userName, clientAddr.toString(), port, new String(srvPortClient),  sessionKey, clientPubKey);
			st.setUserName(userName);

		} else {
			log.info("fail to find the corresponding thread for " + clientAddr);
		}

	}
	
	private void mutualAuthentication() throws Exception{
		log.info("Mutual authentication begins..");
		//Phase2: send a Nonce (as challenge) to client		
		N1 = util.getNextNonce();
		sThread.sendMsgToClient(N1);
		log.info("Send N1 (as challenge) to client: " + N1);
		
		//Phase3: receive the response from client and authenticate the client
		byte[] response1 = sThread.receiveMsgFromClient();
		byte[] response2 = sThread.receiveMsgFromClient();
		Key aesKey = util.getAesKeyFromWrapped(response2, IMserver.serverPrvKey);
		byte[] N2 = checkResponse(response1, aesKey);
		
		//Phase4: send message including the session key to client
		byte[] msgPhase4 = generateMsgPhase4(N2);
		byte[] enMsgPhase4 = util.encryptMsgWithPubKey(clientPubKey, msgPhase4);
		sThread.sendMsgToClient(enMsgPhase4);
		sessionKey = util.generateAESkey();
		byte[] sKey = util.wrapAesKeyWithPubKey(sessionKey, clientPubKey);
		System.out.println("session Key length = " + sKey.length);				
		sThread.sendMsgToClient(sKey);
		
		//Phase5: receive the response from client
		byte[] resp = sThread.receiveMsgFromClient();
		byte[] N4 = checkMsgPhase5(resp);
			
		
		//Phase6: send the confirmation message to client
		byte[] confirmMsg = util.concatAll(N4, CONNECT.getBytes());
		sThread.sendMsgToClient(util.encryptMsgWithAES(sessionKey, confirmMsg));
		log.info("Mutual authentication ends...");
		
	}
	
	
	private byte[] checkResponse(byte[] response, Key aesKey) throws Exception {
		log.info("Checking the response from client from Phase3");
		byte[] responseDec = util.decryptMsgWithAES(aesKey, response);
		byte[] N2 = parseResponseDec(responseDec);	
		return N2;
	}
	
	
	private byte[] decryptWithPrvKey(byte[] msg) throws Exception {
		log.info("Decrypting message with private key of server.");		

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, IMserver.serverPrvKey);
		byte[] decryptedData = cipher.doFinal(msg);
		log.info("SUCCEED Decrypting message with private key of server: ."
				+ new String(decryptedData));
		return decryptedData;

	}
	
	
	/*Parse message sent by client in Phase3, return N2.
	 * */
	private byte[] parseResponseDec(byte[] msg) throws Exception{
		byte[] N1tmp = Arrays.copyOfRange(msg, 0, NONCE_SIZE);
		if(Arrays.equals(N1, N1tmp) == false)  {
			sThread.sendMsgToClient(LOGIN_FAIL.getBytes());
			throw new Exception("Client authentication failed.");
		}
		int start = NONCE_SIZE;
		byte[] N2 = Arrays.copyOfRange(msg, start, start+NONCE_SIZE);
		start += NONCE_SIZE;
		byte[] hashedPwd =  Arrays.copyOfRange(msg, start, start+util.HASHED_PWD_SIZE);
		start += util.HASHED_PWD_SIZE;
		byte[] pubKeyBytes = Arrays.copyOfRange(msg, start, start+util.RSA_KEY_ENCODED_LEN);
		
		clientPubKey = util.recoverPubKey(pubKeyBytes);
		
		start += util.RSA_KEY_ENCODED_LEN;
		byte[] uName = Arrays.copyOfRange(msg, start, msg.length);
		userName = new String(uName);
		isHashedPwdRight(hashedPwd, userName);		
		
		return N2;
	}
	
	

	
	
	private void isHashedPwdRight(byte[] hashedPwd, String userName) throws Exception{
		log.info("Checking whether the hashed pwd is correct.");
		if( Arrays.equals(hashedPwd, IMserver.pwdMap.get(userName)) == false) {
			throw new Exception("Password is not correct.");
		}
	}
	
	
	private byte[] generateMsgPhase4(byte[] N2) throws Exception {
		log.info("Generating the message in Phase4: N2.length=" + N2.length);
		N3 = util.getNextNonce();	
		return util.concatAll(N2, N3);		
	}
	
	
	/*Check the message from client in Phase5, this message is encrypted with session key, 
	 * so that server can make sure the client already get the correct session key*/
	private byte[] checkMsgPhase5(byte[] msg) throws Exception {
		log.info("Checking the message received from client in Phase5, msg length = " + msg.length);
		if(Arrays.equals(msg, LOGIN_FAIL.getBytes()))  {
			throw new Exception("Server failed to authenticate itself to client..");
		}
		
		byte[] deMsg = util.decryptMsgWithAES(sessionKey, msg);
		byte[] N3tmp = Arrays.copyOfRange(deMsg, 0, NONCE_SIZE);
		if(Arrays.equals(N3, N3tmp) == false) {
			sThread.sendMsgToClient(LOGIN_FAIL.getBytes());
			throw new Exception("N3 is not matched.");
		}
		byte[] N4 = Arrays.copyOfRange(deMsg, NONCE_SIZE, NONCE_SIZE*2);
		
		srvPortClient = Arrays.copyOfRange(deMsg, NONCE_SIZE*2, deMsg.length);
		return N4;
	}
	
	
}

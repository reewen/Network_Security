package network.security.client;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import network.security.common.util;

public class authenticationWithServer {

	private String userName;
	private String password;
	private DataInputStream  streamIn   = null;
	private DataOutputStream streamOut = null;
	private Socket socket = null;
	private int srvPort;
	private InetAddress srvAddr = null;
	private String srvName = null;
	// userMap: key = (String) userName, value = (byte[]) salt
	private Map<String, byte[]> userMap = new HashMap<String, byte[]>();
	
	// user's private key and public key in this session.
	private PrivateKey prvKey = null;
	private PublicKey pubKey = null;
	private Key sessionKeyWithServer = null; 
	private int localPort = -1;
	
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() );	

	private static final int MAX_MSG = util.MAX_MSG;
	private static final int NONCE_SIZE = util.NONCE_SIZE;//8bytes, i.e. 64 bits
	private static final int SALT_SIZE = util.SALT_SIZE;// 32 bytes. i.e. 256 bits

	private static final String saltFile = "salts3";
	
	
	// N2, N4 is the nonce created in the phases of authentication with server
	private byte[] N2 = null;
	private byte[] N4 = null;
	
	private ServerSocket s;
	
	private final String LOGIN = "LOGIN_REQUEST";
	private final String CONNECT = "CONFIRM_CONNECTED"; //indicate login is successful 
	private final String LOGIN_FAIL = "SOMETHING ERROR DURING MUTUAL AUTHENTICATION";
	
	private boolean serverRunning = true;
	private final String SERVER_DOWN_ERR_MSG = "Server is not working, login is not available now.";
	
	public authenticationWithServer(InetAddress srvAddr, int srvPort) {
		try {
			this.srvAddr = srvAddr;
			this.srvPort = srvPort;
			log.info("srvAddr=" + srvAddr + ", srvPort=" +  srvPort);
			socket = new Socket(srvAddr, srvPort);
			
			streamIn = new DataInputStream(new BufferedInputStream(
					socket.getInputStream()));
			streamOut = new DataOutputStream(new BufferedOutputStream(
					socket.getOutputStream()));	
			log.info("Succeeded to open a socket for authentication.");
			
		} catch (ConnectException e) {
			System.out.println(SERVER_DOWN_ERR_MSG);
			serverRunning = false;
		}
		
		catch (Exception e) {
			e.printStackTrace();
			log.info("Failed to open a socket for authentication.");
			
		}
		
		
		
		try {
			loadUserSalt();
			log.info("Succeeded to load the user salts file.");
		} catch (Exception e) {
			e.printStackTrace();
			log.info("Failed to load the user salts file.");
			

		}
		
		
		
	}
	

	public void start() throws Exception {		

		while (true) {

			userInput();
			
			if(serverRunning == false) {
				System.out.println(SERVER_DOWN_ERR_MSG);
				throw new Exception(SERVER_DOWN_ERR_MSG);
			}
				

			if (isUserRegistered(userName) == false) {
				System.out
						.println("Sorry, this user is not registered. Please check your user name is right.");
				continue;
			} 
			
			try {
				mutualAuthenticate();
				log.info("Mutual authentication is successful.");
				monitor.userName = userName;
				monitor.sessionKeyWithServer = sessionKeyWithServer; 
				monitor.streamIn_server = streamIn;
				monitor.streamOut_server = streamOut;
				monitor.socket = socket;
				monitor.sSocket = s;
				monitor.localPort = localPort;
				monitor.prvKey = prvKey;
				monitor.pubKey = pubKey;
				break;
			} catch (Exception ex) {
				System.out
				.println("Sorry, failed to authenticate with server because: " + ex.getMessage());
				log.info("Failed to authenticate with server because: " + ex.getMessage());
				ex.printStackTrace();
				sendMsgToServer(LOGIN_FAIL.getBytes());
				continue;
			}		
					

		}
		
		

	}

	public void userInput() throws Exception {
		System.out
				.println("Please login using your USERNAME and PASSWORD, e.g. USER1 PASSWORD");

		InputStreamReader inp = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(inp);
		while (true) {			
			String input = br.readLine();
			int index = input.indexOf(" ");
			if (index > 0 && index < input.length() - 1) {
				String[] parts = input.split(" ");
				if(parts.length != 2) {
					System.out.println("Please enter USERNAME and PASSWORD in a correct form, e.g. USER1 PASSWORD");
					continue;
				}
					
				userName = parts[0];
				password = parts[1];
				break;
			} else {
				System.out
						.println("Please enter USERNAME and PASSWORD in a correct form, e.g. USER1 PASSWORD");
			}

		}

	}

	private boolean isUserRegistered(String userName) {

		return (userMap.containsKey(userName));

	}

	private void loadUserSalt() throws Exception {

		ObjectInputStream in = new ObjectInputStream(new FileInputStream(
				saltFile));
		try {
			List<byte[]> byteList = (List<byte[]>) in.readObject();

			for (byte[] line : byteList) {
				insertToMap(line);
			}
		} finally {
			in.close();
		}
	}

	private void insertToMap(byte[] line) throws Exception {
		byte[] salt = Arrays.copyOfRange(line, 0, SALT_SIZE);
		byte[] uName = Arrays.copyOfRange(line, SALT_SIZE, line.length);
		userMap.put(new String(uName), salt);
	}

	private boolean mutualAuthenticate() throws Exception {
		boolean succeed = false;

		// Phase1: Send greeting to server, request to login
		sendMsgToServer(LOGIN.getBytes());

		// Phase2: Get N1 from server
		byte[] N1 = receiveMsgFromServer();
		if (Arrays.equals(N1, LOGIN_FAIL.getBytes()))
			throw new Exception("ERROR when trying to get N1 from server");

		// Phase3:
		// Generate message for authenticating client to server
		byte[] authMsg = generateAuthMsg(N1);
		
		//Send {N1, N2, hash{Salt|pwd}, K_client(pub), userName}K_tmpAES to server
		Key tmpAES = util.generateAESkey();
		sendMsgToServer(util.encryptMsgWithAES(tmpAES, authMsg));
			
		//send {K_tmpAES} K_server(pub)
		byte[] aesEncrypted = util.wrapAesKeyWithPubKey(tmpAES, IMclient.serverPubKey);
		sendMsgToServer(aesEncrypted);
		

		// Phase4: get the response from server, get N3 and Session Key
		byte[] response1 = receiveMsgFromServer(); 
		byte[] response2 = receiveMsgFromServer();

		byte[] N3 = parseResponse(response1);
		sessionKeyWithServer = util.getAesKeyFromWrapped(response2, prvKey);

		// Phase5: send another message encrypted with session key
		N4 = util.getNextNonce();
		s = new ServerSocket(0);
		
		localPort = s.getLocalPort();
		byte[] msg5 = util.concatAll(N3, N4, String.valueOf(localPort).getBytes());
		byte[] msg5en = util.encryptMsgWithAES(sessionKeyWithServer, msg5);
		sendMsgToServer(msg5en);

		byte[] confirmMsg = receiveMsgFromServer();

		checkConfirm(confirmMsg);

		succeed = true;

		return succeed;

	}
	
	
	private void sendMsgToServer(byte[] msg) {
		log.info("Sending message to server: " + new String(msg));
		try {			
			streamOut.write(msg);	
			streamOut.flush();
			
		} catch (Exception ex) {
			ex.printStackTrace();
			log.info("ERROR sending message to server: " + ex.getMessage());
		}
		
	}
	
	
	
	private byte[] receiveMsgFromServer() {		
		try {	
			byte[] data = new byte[MAX_MSG];
			int bytesNum = streamIn.read(data);
			byte[] msg = new byte[bytesNum];
			System.arraycopy(data, 0, msg, 0, bytesNum);
			log.info("SUCCEED receiving the message from server: " + msg);
			return msg;
		} catch (Exception ex) {
			ex.printStackTrace();
			log.info("ERROR receiving message from server: " + ex.getMessage());
			return null;
		}	
		
	}
	
	
	private byte[] generateAuthMsg(byte[] N1) throws Exception{
		
		N2 = util.getNextNonce();		
		byte[] hashed = util.getHashedPassword(userMap.get(userName), password);
		KeyPair key = util.generateKeyPair();
		prvKey = key.getPrivate();
		pubKey = key.getPublic();
		byte[] uName = userName.getBytes();
		byte[] pubKeyBytes = pubKey.getEncoded();		
		byte[] authMsg = util.concatAll(N1, N2, hashed, pubKeyBytes, uName);
		log.info("Generating the authentication message, size is: " + N1.length + ", " + N2.length + ", " + hashed.length  + ", "+ pubKeyBytes.length + ", " + uName.length);
		return authMsg;
	}
	
	

	
	
	private byte[] parseResponse(byte[] response) throws Exception{
		log.info("Parsing the response from server in Phase 4");
		if(Arrays.equals(response, LOGIN_FAIL.getBytes()) == true)
			throw new Exception("User authentication failed.");
		
		byte[] deResponse = util.decryptMsgWithPrvKey(prvKey, response);
		
		byte[] N2tmp = Arrays.copyOfRange(deResponse, 0, NONCE_SIZE);
		
		if(Arrays.equals(N2, N2tmp) == false) 
			throw new Exception("Server authentication failed.");	
		
		byte[] N3 = Arrays.copyOfRange(deResponse, NONCE_SIZE, NONCE_SIZE*2);
		
		return N3;	
		
	}
	
	
	
	private void checkConfirm(byte[] msg) throws Exception{
		log.info("Checking the confirmation message from server.");
		byte[] deMsg = util.decryptMsgWithAES(sessionKeyWithServer, msg);
		byte[] N4tmp = Arrays.copyOfRange(deMsg, 0, NONCE_SIZE);
		if(Arrays.equals(N4, N4tmp) == false)
			throw new Exception("This confimation message is fake (not from server).");
		
		byte[] conMsg = Arrays.copyOfRange(deMsg, NONCE_SIZE, deMsg.length);
		if(CONNECT.equals(new String(conMsg)) == false)
			throw new Exception ("Failed to connect to server.");
		
	}


}

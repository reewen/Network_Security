package network.security.client;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import network.security.common.util;

public class clientThread extends Thread  {
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	
	String userName = null;
	monitor mo = null;
	Socket socket = null;
	boolean running = true;
	PublicKey srcPubKey = null;
	String srcUserName = null;
	
	
	byte[] data = null;
	PublicKey targetPubKey = null;
	String msgToSend = null;
	
	private DataInputStream  streamIn  =  null;
	private DataOutputStream streamOut = null;
	
	Key secKey = null;
	
	byte[] N1 = null;
	
	//client is asked to set up a connection
	public clientThread(monitor _mo, Socket _socket) {
		this.mo = _mo;
		this.socket = _socket;
		
	}
	
	//client asks to set up a connection 
	public clientThread(monitor _mo, Socket _socket, byte[] data, PublicKey targetPubKey, String msgToSend, String _tgtUserName) {
		this.mo = _mo;
		this.socket = _socket;
		this.data = data;
		this.targetPubKey = targetPubKey;
		this.msgToSend = msgToSend;
		this.userName = _tgtUserName;
	}
	
	
	public String getUserName() {
		return this.userName;
	}
	

	public void open() throws IOException{

		streamIn = new DataInputStream(new BufferedInputStream(
				socket.getInputStream()));
		streamOut = new DataOutputStream(new BufferedOutputStream(
				socket.getOutputStream()));
	}
	
	
	
	
	public void close() {
		System.out.println("close is called..");
		try {
		if(socket != null)
			socket.close();
		if(streamIn != null)
			streamIn.close();
		if(streamOut != null)
			streamOut.close();		
		
		mo.removeClient(userName);
		
		} catch (Exception e) {
			log.info("Failed to close the socket of client " + userName);
			stop();
		}
		
	}
	
	
	public void startPassive() throws Exception {
		log.info("receiver..");
		//Phase1: get the message from other client, check the message
		byte[] data = receiveMsgFromClient();
		byte[] wrappedKey =  receiveMsgFromClient();
		
		Key tmpKey = util.getAesKeyFromWrapped(wrappedKey, mo.prvKey);
		byte[] dataDecrypted = util.decryptMsgWithAES(tmpKey, data);
		
		N1 = Arrays.copyOfRange(dataDecrypted, 0, util.NONCE_SIZE);
		byte[] NsTmp = Arrays.copyOfRange(dataDecrypted, util.NONCE_SIZE, util.NONCE_SIZE*2);
		byte[] ticket = Arrays.copyOfRange(dataDecrypted, util.NONCE_SIZE*2, dataDecrypted.length);
		
		int start = 0;
		byte[] ticketDecrypted = util.decryptMsgWithAES(mo.sessionKeyWithServer, ticket);
		byte[] NsInTicket = Arrays.copyOfRange(ticketDecrypted, 0, start + util.NONCE_SIZE);
		
		if(Arrays.equals(NsTmp, NsInTicket) == false) {
			close();
			throw new Exception("Ns is not matched..");
		}
		start += util.NONCE_SIZE;	
		srcUserName = new String(Arrays.copyOfRange(ticketDecrypted, start, start + util.USERNAME_SIZE));
		userName = srcUserName;
		
		start += util.USERNAME_SIZE;
		
		byte[] pubKeyBytes = Arrays.copyOfRange(ticketDecrypted, start, start+util.RSA_KEY_ENCODED_LEN);
		srcPubKey = util.recoverPubKey(pubKeyBytes);
		
		start+=util.RSA_KEY_ENCODED_LEN;
		String addr = new String(Arrays.copyOfRange(ticketDecrypted, start, ticketDecrypted.length));
		
		byte[] N1En = util.encryptMsgWithPubKey(srcPubKey, N1);
		sendMsgToClient(N1En);
		
		
		secKey = util.generateAESkey();
		byte[] wrappedKey2 = util.wrapAesKeyWithPubKey(secKey, srcPubKey);
		sendMsgToClient(wrappedKey2);
		
		byte[] msgFinal = util.decryptMsgWithAES(secKey, receiveMsgFromClient());
		System.out.println("Received message from " + userName + " : " + new String(msgFinal));
		
		
	}
	
	
	
	public void startPositive() throws Exception{
		
		//Phase 1: send ticket to target user
		Key tmpAES = util.generateAESkey();
		N1 = util.getNextNonce();
		byte[] msg = util.encryptMsgWithAES(tmpAES, util.concatAll(N1, data));
		
		sendMsgToClient(msg);
		
		byte[] wrappedKey = util.wrapAesKeyWithPubKey(tmpAES, targetPubKey);
		
		sendMsgToClient(wrappedKey);
		
		byte[] N1en = receiveMsgFromClient();
		byte[] N1tmp = util.decryptMsgWithPrvKey(mo.prvKey, N1en);
		if(Arrays.equals(N1tmp, N1) == false)
			throw new Exception("N1 is not matched..");
		
		byte[] secKeyBytes = receiveMsgFromClient();
		secKey = util.getAesKeyFromWrapped(secKeyBytes, mo.prvKey);
		
		//Phase2: send message to target user, encrypting it using the session key.
		byte[] msgEn = util.encryptMsgWithAES(secKey, msgToSend.getBytes());
		sendMsgToClient(msgEn);
	}
	
	
	public void run() {
		mo.insterClient(secKey, userName);
		while(running) {
			try {
				byte[] msgDe = util.decryptMsgWithAES(secKey, receiveMsgFromClient());
				System.out.println("Received message from " + userName + " : " + new String(msgDe));
				
			}  catch (Exception e) {
				log.info("Something is wrong during receive the message from other clients.");
				System.out.println("Something is wrong during receive the message from other clients.");
				close();
				stop();
				
			} 
		}
		
		
	}
	
	
	
	public void sendMsgToClient(byte[] msg) {	
		
		mo.sendMsgToSomeone(msg, streamOut);
	}
	
	
	public byte[] receiveMsgFromClient() {

		return mo.receiveMsgFromSomeone(streamIn);
	}

}

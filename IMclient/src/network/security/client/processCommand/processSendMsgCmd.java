package network.security.client.processCommand;

import java.io.IOException;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import network.security.client.clientThread;
import network.security.client.monitor;
import network.security.common.util;

public class processSendMsgCmd {

	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() );	
	monitor mo = null;
	clientThread cThread = null;
	byte[] Na = null;
	byte[] Ns = null;
	String targetUser = null;
	
	
	String targetIp = null;
	PublicKey targetPubKey = null;
	Socket socket = null;
	
	public processSendMsgCmd(monitor _mo) {
		this.mo = _mo;
		
		
	}
	
	
	public void start(String input) throws Exception{
		log.info("Send Command starts..");
		String[] parts = input.split(" ");
		String msgToSend = getMsg(parts[0], parts[1], input);
		try {
		cThread = mo.findClient(parts[1]);
		if(cThread == null)
			initialDialogWithClient(parts[1], msgToSend);
		
		else {
			byte[] msgToSendEncrypt = util.encryptMsgWithAES(mo.clientKeyMap.get(parts[1]), msgToSend.getBytes());
			cThread.sendMsgToClient(msgToSendEncrypt);
			
			
		}	
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception("Something is wrong during send command: " + e.getMessage());
		}
		
	}
	
	
	
	//maybe delete the msgToSend
	public void initialDialogWithClient(String _targetUser, String msgToSend) throws Exception{		
		log.info("This is a new client, need to initial the connection..");	
		
		if(mo.clientCount < mo.clients.length) {
			log.info("Client connection begins to build ..." );
			targetUser = _targetUser;
			byte[] msgPhase1 = generateMsgPhase1(targetUser);
			mo.sendMsgToSomeone(msgPhase1, mo.streamOut_server);
			
			byte[] respPhase2 = mo.receiveMsgFromSomeone(mo.streamIn_server);
			checkResponse(respPhase2);
			
			byte[] ticketToTargetUser = mo.receiveMsgFromSomeone(mo.streamIn_server);
			
						
			byte[] ticketToTargetUserDecrypted = util.decryptMsgWithAES(mo.sessionKeyWithServer, ticketToTargetUser);
			
			
			mo.clients[mo.clientCount] = new clientThread(mo, socket, util.concatAll(Ns, ticketToTargetUserDecrypted), targetPubKey, msgToSend, targetUser);
			try {
				mo.clients[mo.clientCount].open();
				mo.clients[mo.clientCount].startPositive();
				mo.clients[mo.clientCount].start();
				mo.clientCount++; 
			} catch (IOException ioe) {
				log.info("Error opening thread: " + ioe.getMessage());
			}					
			
		} else {
			log.info("Client connection is refused because the number of connections is maximum now, clientCount = " + mo.clientCount);
			
		}
		
		

		
		
		
	}
	
	
	
	private byte[] generateMsgPhase1(String targetUser) throws Exception{
		log.info("Generate message in phase1, request to talk to target user");
		Na = util.getNextNonce();
		String secondPart = util.TALK_REQUEST + targetUser;
		byte[] clearMsg = util.concatAll(Na, secondPart.getBytes());
		return util.encryptMsgWithAES(mo.sessionKeyWithServer, clearMsg);
		
		
	}
	
	
	
	private String getMsg(String send, String userName, String input) throws Exception{
		
		log.info("Get the message which is sent to " + userName + " by " + monitor.userName);
		int offset = send.length() + 1 + userName.length() + 1;
		return input.substring(offset);
		
	}
	
	
	private void checkResponse(byte[] respPhase2) throws Exception {
		log.info("Checking the response from server, and get the information from B");
		
		byte[] decyptedRespPhase2 =  util.decryptMsgWithAES(mo.sessionKeyWithServer, respPhase2);
		
		String tmp = new String (decyptedRespPhase2);
		if(tmp.equals(util.NOT_ONLINE) == true) {
			System.out.println(tmp);
			throw new Exception(tmp);
		}
		
		int start = 0;
		byte[] NaTmp = Arrays.copyOfRange(decyptedRespPhase2, start, start + util.NONCE_SIZE);
		if(Arrays.equals(Na, NaTmp) == false) {
			throw new Exception("Na is not matched..");
		}
		
		start += util.NONCE_SIZE;
		Ns = Arrays.copyOfRange(decyptedRespPhase2, start, start + util.NONCE_SIZE);
		
		start += util.NONCE_SIZE;
		byte[] targetName = Arrays.copyOfRange(decyptedRespPhase2, start, start + util.USERNAME_SIZE);
		
		if(targetUser.equals(new String(targetName)) == false) 
			throw new Exception ("Target user is not matched..");
		
		start += util.USERNAME_SIZE;
		
		byte[] targetPubKeybytes = Arrays.copyOfRange(decyptedRespPhase2, start, start + util.RSA_KEY_ENCODED_LEN);
		targetPubKey = util.recoverPubKey(targetPubKeybytes);
		
		start += util.RSA_KEY_ENCODED_LEN;
		
		byte[] targetAddr = Arrays.copyOfRange(decyptedRespPhase2, start, decyptedRespPhase2.length);
		
		String targetAddrString = new String(targetAddr);
		String[] parts = targetAddrString.split(" ");
		socket = new Socket(parts[0], Integer.parseInt(parts[1]));
		
		
	}
	
	
}
	
	
	
	
	
	
	
	
	
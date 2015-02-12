package network.security.client.processCommand;

import java.util.Arrays;
import java.util.logging.Logger;

import network.security.client.monitor;
import network.security.common.util;

public class processListCmd {
	
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() );	
	monitor mo = null;
	byte[] N1 = null;
	
	
	public processListCmd(monitor _mo) {
		
		this.mo = _mo;
		
	}
	
	
	public void start() throws Exception{
		try {
		log.info("Sending LIST_REQUEST to server..");
		//Phase1: send LIST_REQUEST to server
		N1 = util.getNextNonce();
		byte[] msgEncypted = util.encryptMsgWithAES(mo.sessionKeyWithServer, util.concatAll(N1, util.LIST_REQUEST.getBytes()));
		mo.sendMsgToSomeone(msgEncypted, mo.streamOut_server);
		
		log.info("Receiving response from server");
		//Phase2: receive response from server
		byte[] data = mo.receiveMsgFromSomeone(mo.streamIn_server);
		byte[] response =  getList(data);
		log.info("Print the list of client names");
		//Phase3: print the response on console
		System.out.println("Here is the list of online users:");
		System.out.println(new String(response));
		log.info("LIST_REQUEST ends..");
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
		
	}
	
	private byte[] getList(byte[] msg) throws Exception {
		log.info("Check the message from server, and get the list of clients from the message");
		byte[] msgDecrypted = util.decryptMsgWithAES(mo.sessionKeyWithServer, msg);
		byte[] N1tmp = Arrays.copyOfRange(msgDecrypted, 0, util.NONCE_SIZE);
		if(Arrays.equals(N1, N1tmp) == false)
			throw new Exception("N1 is not matched..");
		
		return Arrays.copyOfRange(msgDecrypted, util.NONCE_SIZE, msgDecrypted.length);	
		
	}

}

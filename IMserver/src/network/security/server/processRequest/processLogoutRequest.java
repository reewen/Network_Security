package network.security.server.processRequest;

import java.security.Key;
import java.util.Arrays;
import java.util.logging.Logger;

import network.security.common.util;
import network.security.server.monitor;
import network.security.server.serverThread;

public class processLogoutRequest {
	
	monitor mo = null;
	serverThread sThread = null;
	byte[] N2 = null;
	Key sessionKey = null;
	byte[] tmpNonce = null;
	
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	
	public processLogoutRequest(monitor mo) {
		this.mo = mo;
		
	}
	
	public void start(byte[] N1, String userName) throws Exception {
		
		try {
		tmpNonce = N1;
		sThread = mo.findClient(userName);
		this.sessionKey = monitor.sessionKeyMap.get(userName);
		N2 = util.getNextNonce();
		
		sThread.sendMsgToClient(util.encryptMsgWithAES(sessionKey, util.concatAll(N1, N2)));
		
		byte[] res = sThread.receiveMsgFromClient();
		byte[] resDe = util.decryptMsgWithAES(sessionKey, res);
		
		byte[] N2tmp = Arrays.copyOfRange(resDe, 0, util.NONCE_SIZE);
		if(Arrays.equals(N2, N2tmp) == false) {
			throw new Exception("N2 is not matched, user authentication failed.");			
		}
		
		byte[] N3 = Arrays.copyOfRange(resDe, util.NONCE_SIZE, resDe.length);		
		tmpNonce = N3;
		sThread.sendMsgToClient(util.encryptMsgWithAES(sessionKey, util.concatAll(N3, util.LOGOUT_SUCCEED.getBytes())));
		} catch (Exception e) {
			log.info("ERROR when trying to logout client " + userName + ": " + e.getMessage() );
			sThread.sendMsgToClient(util.encryptMsgWithAES(sessionKey, util.concatAll(tmpNonce, util.LOGOUT_FAIL.getBytes())));
			throw e;
		}
		
	}
	
	

}

package network.security.server.processRequest;

import java.util.logging.Logger;

import network.security.common.util;
import network.security.server.monitor;
import network.security.server.serverThread;

public class processSendRequest {
	
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() );	
	
	private serverThread srcThread = null;
	private monitor mo = null;
	private String srcUser;
	private String targetUser;
	
	public processSendRequest(monitor _mo, String srcUser, String targetUser) {
		this.mo = _mo;
		this.srcUser = srcUser;
		this.targetUser = targetUser;
	}
	
	public void start(byte[] N1) throws Exception{
		log.info("processSendRequest starts...");
		srcThread = mo.findClient(srcUser);
		
		if(mo.ipMap.containsKey(targetUser) == false) {
			byte[] errMsg = util.encryptMsgWithAES(mo.sessionKeyMap.get(srcUser), util.NOT_ONLINE.getBytes());
			srcThread.sendMsgToClient(errMsg);
			throw new Exception("Target user is not online now. Sending message to this user is not available now.");
		}
		
		byte[] Ns = util.getNextNonce();
		
		byte[] msgForSrcEncypted = generateMsgForSrc(N1, Ns);
		srcThread.sendMsgToClient(msgForSrcEncypted);		
		
		byte[] ticket = generateTicket(srcUser, Ns, targetUser);
		
		
		byte[] ticketEncrypted = util.encryptMsgWithAES(mo.sessionKeyMap.get(srcUser), ticket);
		srcThread.sendMsgToClient(ticketEncrypted);	
	}
	
	
	private byte[] generateMsgForSrc(byte[] N1, byte[] Ns) throws Exception {
		log.info("Generating the message for source user to read...");
		
		String str = getStringFromIpMap(targetUser);
		
		byte[] msg = util.concatAll(N1, Ns, targetUser.getBytes(), mo.pubKeyMap.get(targetUser).getEncoded(),str.getBytes());
		
		return util.encryptMsgWithAES(mo.sessionKeyMap.get(srcUser), msg);
		
	}
	
	private byte[] generateTicket(String srcUser, byte[] Ns, String targetUser) throws Exception{
		
		log.info("Generating the ticket to " + targetUser);
		
		String str = getStringFromIpMap(srcUser);
		
		byte[] msg = util.concatAll(Ns, srcUser.getBytes(), mo.pubKeyMap.get(srcUser).getEncoded(), str.getBytes() );
		
		return util.encryptMsgWithAES(mo.sessionKeyMap.get(targetUser), msg);
		
	}
	
	private String getStringFromIpMap(String uName) {
		Object[] os = mo.ipMap.get(uName);
		StringBuilder str = new StringBuilder();
		str.append(os[0].toString().substring(1));
		str.append(" ");
		str.append(os[1].toString());
		System.out.println("target address in string: " +  str);
		return str.toString();
	}

}

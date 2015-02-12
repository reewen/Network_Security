package network.security.server.processRequest;

import java.util.Set;
import java.util.logging.Logger;

import network.security.common.util;
import network.security.server.monitor;
import network.security.server.serverThread;

public class processListRequest {
	private final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	

	
	private serverThread sThread = null;
	
	public void start(monitor mo, int id, byte[] N1) throws Exception{
		log.info("Processing list request from thread " + id);
		
		sThread = mo.findClient(id);
		
		Set<String> nameList = mo.getClientNameList();
		StringBuilder listResp = new StringBuilder();
		
		for(String str : nameList) {
			listResp.append(str);
			listResp.append(" ");
		}
		
		log.info("List of online clients are: " + listResp.toString());
		
		byte[] clearMsg = util.concatAll(N1, listResp.toString().getBytes());
		
		
		sThread.sendMsgToClient(util.encryptMsgWithAES(monitor.sessionKeyMap.get(sThread.getUserName()), clearMsg));
	}
	

}

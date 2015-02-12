package network.security.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.Key;
import java.util.Arrays;
import java.util.logging.Logger;

import network.security.common.util;
import network.security.server.processRequest.processListRequest;
import network.security.server.processRequest.processLoginRequest;
import network.security.server.processRequest.processLogoutRequest;
import network.security.server.processRequest.processSendRequest;

public class serverThread extends Thread {
	
	private monitor mo = null;
	private Socket socket = null;
	private DataInputStream  streamIn  =  null;
	private DataOutputStream streamOut = null;
	private int id = -1; //indicate the port of client 
	private String userName = null;
	private Key sessionKey = null;
	private InetAddress clientAddr = null;
	
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	
	
	private final int MAX_MSG = 65507;
	private boolean running = true;
	
	

	public serverThread(monitor _mo, Socket _socket) {
		super();
		mo = _mo;
		socket = _socket;
		id = socket.getPort();
		clientAddr  = socket.getInetAddress();
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
			log.info("Failed to close the socket of client " + id);
			
		}
		
	}

	@SuppressWarnings("deprecation")
	public void run() {
		log.info("Server Thread " + id + " running.");
		while (running) {
			try {
				if(processMsg(clientAddr, id, receiveMsgFromClient()) == true) {
					System.out.println("Client" + userName + " EORROR processing message");
					continue;
				}
				
			} catch (SocketException se) {
				log.info("Connection with client " + id + " is interrupted. ");
				close();
				stop();
			} 
			catch (IOException ioe) {
				log.info(id + " ERROR reading: " + ioe.getMessage());
				close();
				stop();
			} 
			
		}		
		
	}
	
	
	public void sendMsgToClient(byte[] data) {
		try {
			streamOut.write(data);
			streamOut.flush();		
			log.info("SUCCEED sending message to client " + id +": " + new String(data));
		} catch (IOException ioe ) {
			ioe.printStackTrace();
			log.info(id + " ERROR sending: " + ioe.getMessage());
		}	
		
	}
	
	
	public int getID() {
		return this.id;
	}
	
	public InetAddress getCilentIpAddr() {
		return this.clientAddr;
	}
	
	
	public byte[] receiveMsgFromClient() throws IOException{
		
		
		try {	
			byte[] data = new byte[MAX_MSG];
			int bytesNum = streamIn.read(data);
			byte[] msg = new byte[bytesNum];
			System.arraycopy(data, 0, msg, 0, bytesNum);
			log.info("SUCCEED Receiving the message from client: " + new String(msg));
			return msg;
		} catch (IOException ex) {
			ex.printStackTrace();
			log.info("ERROR receiving message from client: " + ex.getMessage());
			throw ex;
		}
		
	}
	
	private boolean processMsg(InetAddress clientAddr, int port, byte[] msg){
		
		boolean illegal = false;
		try {
			String msgString = new String (msg);
			if (msgString.equals(util.LOGIN_REQUEST)) {
				processLoginRequest p = new processLoginRequest();
				p.start(mo, clientAddr, port, this, msgString);
				if(userName == null)
					throw new Exception("Failed to set the UserName in this thread.");
				sessionKey = monitor.sessionKeyMap.get(userName);
				
			} else {
				
				byte[] clearMsg = util.decryptMsgWithAES(sessionKey, msg);
				
				String tmpMsg = new String(Arrays.copyOfRange(clearMsg, util.NONCE_SIZE, clearMsg.length));
				byte[] N1 = Arrays.copyOfRange(clearMsg, 0, util.NONCE_SIZE);
				if(tmpMsg.equals(util.LIST_REQUEST)) {
					processListRequest p = new processListRequest();
					p.start(mo, port, N1);
				} else if(tmpMsg.equals(util.LOGOUT_REQUEST)) {
					processLogoutRequest p = new processLogoutRequest(mo);
					p.start(N1, userName);
					mo.removeClient(userName);					
				}
				else {
					/*This must be the SEND request*/
					String targetUser = tmpMsg.substring(util.TALK_REQUEST.length());
					processSendRequest p = new processSendRequest(mo, userName, targetUser);
					p.start(N1);
					
				}
						
						
			}
				
				
		} catch (Exception ex) {
			ex.printStackTrace();
			illegal = true;
		}
		return illegal;

	}
	
	
	public void setUserName(String uName) {
		this.userName = uName;
	}
	
	public String getUserName() {
		return this.userName;
	}
	

}

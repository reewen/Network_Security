package network.security.client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import network.security.client.processCommand.processListCmd;
import network.security.client.processCommand.processLogoutCmd;
import network.security.client.processCommand.processSendMsgCmd;
import network.security.common.util;


public class monitor {

	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	public int THREADS_MAX = 4;
	private boolean running = true; 
	private String LIST = "list";
	private String LOGOUT = "logout";
	public static DataInputStream  streamIn_server   = null;
	public static DataOutputStream streamOut_server = null;
	public static Socket socket;
	public static ServerSocket sSocket  = null;
	public static int localPort = -1;
	
	private int srvPort;
	private InetAddress srvAddr = null;
	private String srvName = null;
	public clientThread clients[] = new clientThread[THREADS_MAX]; // Can at most talk to 4 clients at the same time.
	// session key with other users.
	public Map<String, Key> clientKeyMap =  new HashMap<String, Key>();
	public int clientCount = 0;
	
	public static String  userName;
	public static Key sessionKeyWithServer = null; 
	public static PublicKey pubKey = null;
	public static PrivateKey prvKey = null;
	
	private static final int MAX_MSG = util.MAX_MSG;
	
	private monitorConnectionThread mcThread = null;
	
	
	public monitor(InetAddress srvAddr, int srvPort) {
		log.info("Initial monitor class: srvAddr=" + srvAddr + ", srvPort=" + srvPort);
		this.srvAddr = srvAddr;
		this.srvPort = srvPort;		
		start();
	}
	
	
	private void start() {

		while (running) {
			try {
				authenticationWithServer au = new authenticationWithServer(
						srvAddr, srvPort);
				au.start();
				System.out.println("Welcome, " + userName);
				break;

			} catch (Exception e) {
				log.info("ERROR when doing authentication");
				continue;
			}

		}
		
		monitorMsgFromOtherClient();
		monitorUserInput();

	}
	
	private void stop() {
		log.info("Client is teminated.. " );
		running = false;
		mcThread.stop();
	}
	
	
	private void monitorMsgFromOtherClient() {
		log.info("Monitor the message sent by other client..");
		try {
		mcThread = new monitorConnectionThread(this);
		mcThread.start();
		} catch (Exception e) {
			e.printStackTrace();
			stop();
		}
		
	}
	
	private void monitorUserInput() {

		running = true;		
		while (running) {
			try {
				InputStreamReader inp = new InputStreamReader(System.in);
				BufferedReader br = new BufferedReader(inp);
				String input = br.readLine().trim();
				if(input.equals(LIST)) {
					processListCmd p = new processListCmd(this);
					p.start();
				} else if(input.equals(LOGOUT)) {
					processLogoutCmd p = new processLogoutCmd(this);
					p.start();
					break;
				} else if( validateSendCmd(input)) {
					processSendMsgCmd p = new processSendMsgCmd(this);
					p.start(input);
					
				} else {
					throw new Exception("This command is not supported, please re-enter.");
				}			
				
				

			} catch (Exception e) {
				log.info("ERROR processing this command because:" + e.getMessage());
				continue;

			}

		}
		stop();

	}
	

	
	public void sendMsgToSomeone(byte[] msg, DataOutputStream dout) {
		
		try {			
			dout.write(msg);	
			dout.flush();
			log.info("SUCCEED Sending message to someone: " + msg);
		} catch (Exception ex) {
			ex.printStackTrace();
			log.info("ERROR sending message to someone: " + ex.getMessage());
		}	
		
	}
	
	
	public byte[] receiveMsgFromSomeone(DataInputStream streamIn) {
		try {	
			byte[] data = new byte[MAX_MSG];
			int bytesNum = streamIn.read(data);
			byte[] msg = new byte[bytesNum];
			System.arraycopy(data, 0, msg, 0, bytesNum);
			log.info("SUCCEED receiving the message from someone: " + msg);
			return msg;
		} catch (Exception ex) {
			ex.printStackTrace();
			log.info("ERROR receiving message from someone: " + ex.getMessage());
			return null;
		}	
	}
	
	
	private boolean validateSendCmd(String input) throws Exception{
		boolean isValidated = true;
		try {
			String parts[] = input.split(" ");
			if(parts.length < 3) {
				throw new Exception("The format of SEND command is not correct.");
			}
			if(parts[0].equals("send") == false)
				throw new Exception("The first word should be send: send USER MESSAGE");						
			
		} catch (Exception e) {
			e.printStackTrace();
			isValidated = false;
		}
		
		return isValidated;
		
		
	}
	
	public synchronized clientThread findClient(String userName) {
		for(int i=0; i<clientCount; i++) {
			if(clients[i].getUserName().equals(userName))
				return clients[i];
		}
		return null;	
		
	}
	
	
	public synchronized int getClientPos(String userName) {
		for(int i=0; i<clientCount; i++) {
			if(clients[i].getUserName().equals(userName))
				return i;
		}
		return -1;
	}
	
	public synchronized void removeClient(String userName) {
		
		log.info("Removing the client thread " + userName);
		clientKeyMap.remove(userName);
		
		int pos = getClientPos(userName);
		if(pos>=0) {
			clientThread toTerminate = clients[pos];
			if(pos<clientCount-1)
				for (int i = pos+1; i<clientCount; i++)
					clients[i-1] = clients[i];
			
			clientCount--;			
			
		}
		
	}
	
	public synchronized void insterClient(Key secKey, String uName) {
		log.info("Insert the client thread " + userName);
		clientKeyMap.put(uName, secKey);
		log.info("clientKeyMap size after insert is: " + clientKeyMap.size());
	}
	
	
}

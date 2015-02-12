package network.security.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.Key;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import network.security.server.processRequest.*;

public class monitor {
	//key - value: userName - {client's inetAddress, client's serverPort}  
	public static Map<String, Object[]> ipMap = new HashMap<String, Object[]>();
	
	//key - value: userName - client's port, which is used to talk with server
	public static Map<String, Integer> portMap = new HashMap<String, Integer>();
	
	//key - value: userName - sessionKey (used to talk with client)
	public static Map<String, Key> sessionKeyMap = new HashMap<String, Key>();
	
	//key - value: userName - client's public key, this key will be removed if the client log out
	public static Map<String, PublicKey> pubKeyMap = new HashMap<String, PublicKey>();
	
	private int THREADS_MAX = 5; //indicate the maximum number of clients that server can deal with at the same time
	private int SERVER_PORT = 6666;
	private serverThread clients[] = new serverThread[THREADS_MAX]; 	// ipMap: key = userName, value = ipAddress
	
	private ServerSocket socket = null;
	private static int clientCount = 0;
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	private boolean running = false;
	
	

	
	public monitor() {
		
		try {
			log.info("Binding to port " + SERVER_PORT + ", please wait...");
			socket = new ServerSocket(SERVER_PORT);
			start();		
			
		} catch (IOException ioe) {
			log.info("Can not bind to port " + SERVER_PORT + ": " + ioe.getMessage());
		}	
		
	}

	public void start() {
		running = true;
		log.info("Successfully bind to port " + SERVER_PORT);
		while(running) {
			try {
				newClientConnection(socket.accept());				
				
			} catch (IOException ioe) {
				log.info("Server accept an error:" + ioe.getMessage());
				stop();
			}
			
			
		}
		
	}

	public void stop() {
		log.info("Server is terminated.");
		running = false;
	}
	
	public void newClientConnection(Socket socket) {
		
		if(clientCount < clients.length) {
			log.info("Client connection is accepted: " + socket);
			clients[clientCount] = new serverThread(this, socket);
			try {
				clients[clientCount].open();
				clients[clientCount].start();
				clientCount++; 
			} catch (IOException ioe) {
				log.info("Error opening thread: " + ioe.getMessage());
			}					
			
		} else {
			log.info("Client connection is refused because the number of connections is maximum now, clientCount = " + clientCount);
			
		}		
		
	}
	
	
	public serverThread findClient(int id) {
		for(int i=0; i < clientCount; i++)
			if(clients[i].getID() == id)
				return clients[i];
		return null;
	}
	
	public serverThread findClient(String userName) {
		for(int i=0; i< clientCount; i++) {
			if(clients[i].getUserName().equals(userName))
				return clients[i];
		}
		return null;	
		
	}
	
	public serverThread findClient(InetAddress clientAddr, int id) {
		for(int i=0; i< clientCount; i++) {
			if(clients[i].getCilentIpAddr().toString().equals(clientAddr.toString()) && clients[i].getID() == id)
				return clients[i];
		}
		return null;	
	}

	
	public synchronized void insertClient(String uName, String clientAddr, int id, String clientSrvPort, Key sessionKey, PublicKey clientPubKey) {
		log.info("Insert client: IpAddress=" + clientAddr + ", sessionKey = " + sessionKey);
		Object[] value = {clientAddr, clientSrvPort};
		ipMap.put(uName, value);
		portMap.put(uName, id);
		sessionKeyMap.put(uName, sessionKey);
		pubKeyMap.put(uName, clientPubKey);
		
	}
	

	public synchronized int getClientPos(String userName) {
		for(int i=0; i<clientCount; i++) {
			if(clients[i].getUserName().equals(userName))
				return i;
		}
		return -1;
	}
	
	
	
	public synchronized void removeClient(String uName) {
		log.info("Remove client: userName = " + uName);
		ipMap.remove(uName);
		sessionKeyMap.remove(uName);	
		pubKeyMap.remove(uName);
		portMap.remove(uName);
		

		int pos = getClientPos(uName);
		if(pos>=0) {
			serverThread toTerminate = clients[pos];
			if(pos<clientCount-1)
				for (int i = pos+1; i<clientCount; i++)
					clients[i-1] = clients[i];
			
			clientCount--;
			try {
				toTerminate.close();
			} catch (Exception e) {
				log.info("ERROR closing the client thread " + uName);
				toTerminate.stop();
			}
			
		}
		
	
	}
	
	public synchronized Set<String> getClientNameList() {
		log.info("Get the list of names of online clients.. ");
		return ipMap.keySet();
		
	}
	
}

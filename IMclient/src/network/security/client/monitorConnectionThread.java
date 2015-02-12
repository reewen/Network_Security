package network.security.client;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;


public class monitorConnectionThread extends Thread{

	private ServerSocket socket = null;
	private boolean running = true;
	
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() ); 
	
	private monitor mo;
	
	
	public monitorConnectionThread(monitor _mo) throws Exception {
		this.mo = _mo;
		this.socket = mo.sSocket;
	}
	
	public void run() {
		
		while(running) {
			try {
			newClientConnection(socket.accept());		
			} catch (Exception e) {
				e.printStackTrace();
				log.info("Something is wrong when the connection is established.");
			}
			
		}
		
		
	}
	
	
	public void newClientConnection(Socket socket) {
		
		if(mo.clientCount < mo.clients.length) {
			log.info("Client connection is accepted: " + socket);
			mo.clients[mo.clientCount] = new clientThread(mo, socket);
			try {
				mo.clients[mo.clientCount].open();
				mo.clients[mo.clientCount].startPassive();
				mo.clients[mo.clientCount].start();
				mo.clientCount++; 
			} catch (IOException ioe) {
				log.info("Error opening thread: " + ioe.getMessage());
			} catch (Exception e) {
				log.info("Error opening thread: " + e.getMessage());
			}
			
		} else {
			log.info("Client connection is refused because the number of connections is maximum now, clientCount = " + mo.clientCount);
			
		}		
		
	}
	
	
}

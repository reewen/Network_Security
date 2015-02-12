package network.security.client;

import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.util.Properties;
import java.util.logging.Logger;

import network.security.common.util;



public class IMclient {
	
	public static InetAddress srvAddr = null;
	public static String srvName = null;
	public static int srvPort;
	public static PublicKey serverPubKey;
	
	
	private static final String serverConfigFile = "config.properties";
	private static final String SERVER_PUBLIC_KEY_FILE = "server_public_key.der";
	
	
	
	private static final Logger log = Logger.getLogger(Thread.currentThread().getStackTrace()[0].getClassName() );
		
	
	public static void main(String args[]) {
		
		try {
			
			readServerInfo();
			loadServerPubKey();
			
			monitor mo = new monitor(srvAddr, srvPort);

			
		} catch (Exception ex) {
			ex.printStackTrace();
		}	
		
		
	}
	
	public static void readServerInfo() throws Exception {
		log.info("Reading server informatio from properties file...");
		Properties prop = new Properties();
		FileInputStream input = null;

		input = new FileInputStream(serverConfigFile);
		prop.load(input);

		srvName = prop.getProperty("ip");
		srvAddr = InetAddress.getByName(srvName);
		srvPort = Integer.parseInt(prop.getProperty("port"));
	}
	
	public static void loadServerPubKey() throws Exception {
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		serverPubKey = util.getPublicKey(SERVER_PUBLIC_KEY_FILE, rsaKeyFactory);
	}
	
	

}

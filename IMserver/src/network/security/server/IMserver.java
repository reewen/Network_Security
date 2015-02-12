package network.security.server;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import network.security.server.init;

public class IMserver {	

	// pwdMap: key = userName, value = hashed password
	public static Map<String, byte[]> pwdMap = new HashMap<String, byte[]>();	
	
	public static PrivateKey serverPrvKey= null;
	

	public static void main(String args[]) {
		try {
			init serverInit = new init();
			serverInit.start();
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		monitor server = new monitor();

		try {
			server.start();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	

}

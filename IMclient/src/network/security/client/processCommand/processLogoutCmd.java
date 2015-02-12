package network.security.client.processCommand;

import java.util.Arrays;
import java.util.logging.Logger;

import network.security.client.monitor;
import network.security.common.util;

public class processLogoutCmd {

	private static final Logger log = Logger.getLogger(Thread.currentThread()
			.getStackTrace()[0].getClassName());
	monitor mo = null;
	byte[] N1 = null;
	byte[] N3 = null;

	public processLogoutCmd(monitor _mo) {
		this.mo = _mo;
	}

	public void start() throws Exception {
		log.info("Lougout begins...");
		// Phase1: send {N1, LOGOUT_REQUEST}k to server
		while (true) {
			N1 = util.getNextNonce();
			byte[] msgPhase1 = util.encryptMsgWithAES(mo.sessionKeyWithServer,
					util.concatAll(N1, util.LOGOUT_REQUEST.getBytes()));
			mo.sendMsgToSomeone(msgPhase1, mo.streamOut_server);

			// Phase2: verify server
			byte[] res = mo.receiveMsgFromSomeone(mo.streamIn_server);
			byte[] resDecrypted = util.decryptMsgWithAES(
					mo.sessionKeyWithServer, res);
			byte[] N1tmp = Arrays.copyOfRange(resDecrypted, 0, util.NONCE_SIZE);
			if (Arrays.equals(N1, N1tmp) == false) {
				log.info("N1 is not matched..");
				System.out
						.println("LOGOUT FALIED, TRY AGAIN NOW, PLEASE WAIT..");
				continue;
			}

			byte[] N2 = Arrays.copyOfRange(resDecrypted, util.NONCE_SIZE,
					resDecrypted.length);

			if (util.LOGOUT_FAIL.equals(new String(N2))) {
				log.info("Get logout fail message from server.");
				System.out
						.println("LOGOUT FALIED, TRY AGAIN NOW, PLEASE WAIT..");
				continue;
			}

			// Phase3: authenticate client itself to server
			N3 = util.getNextNonce();
			mo.sendMsgToSomeone(
					util.encryptMsgWithAES(mo.sessionKeyWithServer,
							util.concatAll(N2, N3)), mo.streamOut_server);

			byte[] confirmMsg = mo.receiveMsgFromSomeone(mo.streamIn_server);
			byte[] confirmMsgDe = util.decryptMsgWithAES(
					mo.sessionKeyWithServer, confirmMsg);
			byte[] N3tmp = Arrays.copyOfRange(confirmMsgDe, 0, util.NONCE_SIZE);
			if (Arrays.equals(N3, N3tmp) == false) {
				log.info("N3 is not matched..");
				System.out
						.println("LOGOUT FALIED, TRY AGAIN NOW, PLEASE WAIT..");
				continue;
			}

			byte[] restMsg = Arrays.copyOfRange(confirmMsgDe, util.NONCE_SIZE,
					confirmMsgDe.length);

			if (util.LOGOUT_SUCCEED.equals(new String(restMsg))) {
				log.info("Logout succeed");
				System.out.println("LOGOUT SUCCEED");
				break;
			} else {
				log.info("Get logout fail message from server.");
				System.out
						.println("LOGOUT FALIED, TRY AGAIN NOW, PLEASE WAIT..");
				continue;
			}

		}

	}

}

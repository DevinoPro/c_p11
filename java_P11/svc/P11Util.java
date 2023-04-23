
import java.io.IOException;
import java.util.Scanner;

import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class P11Util {

	public static long GetSlot(PKCS11 pkcs11, boolean private_objects, boolean print_used, String name)
	{
		int islot = 0;
		long[] pslots; 
		CK_TOKEN_INFO tinfo = null;
		// Get OCS Name
//		String label = "TESTSWCARD" ; // SW Protection         
//		if(private_objects)
//		{
//			System.out.print("Input Token Name: ");
//			Scanner scan = new Scanner(System.in); 
//			label = padRight(scan.next(), 32);
//			//scan.close();		
//        }
//        System.out.println("label::" + label + "::"+ label.length());
//        System.out.println("label::" + labelcomp + "::"+ labelcomp.length());

        String label = padRight(name, 32);


		if(label != null) {
			if(label.length() > 32) {
				throw new TokenLabelException("Label can only be 32 chars long");
			}
		}

		try {
			pslots = pkcs11.C_GetSlotList(true);

			if(!private_objects)
				return pslots[0];

			for(islot = 0; islot < pslots.length; islot++) {
				tinfo = pkcs11.C_GetTokenInfo(pslots[islot]);

				String tmp = new String(tinfo.label);
				if(label.compareTo(tmp/*new String(tinfo.label)*/) != 0)
					continue;

				if(print_used) {
					System.out.print("Using token with label \"");
					System.out.println(tinfo.label);
				}
				break;
			}
			if (islot < pslots.length) 
				return pslots[islot];
			else
				throw new TokenLabelException("CKR_TOKEN_NOT_PRESENT");
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return -1;
	}

	public static void Login(PKCS11 pkcs11, long hSession, String sw) throws IOException {

//      String passphrase = "" ; 
//		System.out.print("Input Password: ");
//		Scanner scan = new Scanner(System.in);
//		passphrase = scan.next();
//
		try {
			pkcs11.C_Login(hSession, PKCS11Constants.CKU_USER, sw.toCharArray());
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static String padRight(String s, int n) {
		return String.format("%1$-" + n + "s", s);
	}

}

class TokenLabelException extends RuntimeException {
	TokenLabelException(){
		super();
	}
	TokenLabelException(String message){
		super(message);
	}
}

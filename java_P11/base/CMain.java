//package p11test;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;

import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;



public class CMain {
    
    
    public static boolean isWindows() {
        return (OS.indexOf("win") >= 0);
    }

    public static boolean isUnix() {
        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0 );
    }

    private static String OS = System.getProperty("os.name").toLowerCase();


	public static void main(String[] args){

		PKCS11 pkcs11 = null;
		long[] slotList;
		long hSlot, hSession, hPuK, hPrK;
        int status = 0;

        for (int iii = 0 ; iii  < args.length ; iii++)
        {
            System.out.println("input-" + iii +" ::" +  args[iii]  );
            if(args[0].equals("CREATE"))
            {
                status = 1; 
            }
            else if(args[0].equals("USE"))
            {
                status = 2; 
            }
        }

        if(status ==0)
        {
            System.out.println ("input param is CREATE or USE");
	        System.out.println("END OF PROGRAM\n");
            return ;
        }

		try {
            if(isWindows())
            {
                System.out.println("windows");
                pkcs11 = PKCS11.getInstance("C:\\Program Files (x86)\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast-64.dll", "C_GetFunctionList", null, false);

            }else if (isUnix())
            {
                System.out.println("unix or linux");
                pkcs11 = PKCS11.getInstance("/opt/nfast/toolkits/pkcs11/libcknfast.so", "C_GetFunctionList", null, false);
            }

			// Get Slot & Token Info
			slotList = pkcs11.C_GetSlotList(true);
			hSlot = slotList[0];
			CK_TOKEN_INFO token = pkcs11.C_GetTokenInfo(hSlot);
			System.out.println("#############################################################");
			System.out.println("Information of Module:");
			System.out.println("Token Info: "+token.toString());
			System.out.println("#############################################################");

			// Open Session
			hSession = pkcs11.C_OpenSession(hSlot, PKCS11Constants.CKF_RW_SESSION | PKCS11Constants.CKF_SERIAL_SESSION, null, null);

            if(status==1){
                System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~CREATE KEY");

                // Generate RSA Keypair		
                P11RSAKeyPair rsaKeypair = new P11RSAKeyPair(pkcs11, hSession);
                hPuK = rsaKeypair.hPuK;
                hPrK = rsaKeypair.hPrK;

                System.out.println("Public Key Handle: " + hPuK);
                System.out.println("Private Key Handle: " + hPrK);
                System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~CREATE KEY END");
            }
            else if(status ==2)
            {
                System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~FIND KEY AND SIGN");
                // Find RSA Keypair
                String keyname = "testrsakey";
                P11RSAKeyPair rsaKeypair = new P11RSAKeyPair(pkcs11, hSession, keyname);
                hPuK = rsaKeypair.hPuK;
                hPrK = rsaKeypair.hPrK;

                System.out.println("Public Key Handle: " + hPuK);
                System.out.println("Private Key Handle: " + hPrK);


                // PKCS RSA Signing
                byte[] msg = "testing mesg".getBytes();
                byte[] sig;
                CK_MECHANISM signMech = new CK_MECHANISM();
                signMech.mechanism = PKCS11Constants.CKM_RSA_PKCS;
                pkcs11.C_SignInit(hSession, signMech, hPrK);
                sig = pkcs11.C_Sign(hSession, msg);
                System.out.println("PKCS RSA Signature: " + Hex.toHexString(sig));


                pkcs11.C_VerifyInit(hSession, signMech, hPuK);
                pkcs11.C_Verify(hSession, msg, sig);
                System.out.println("PKCS RSA Verify OK");


                // RAW RSA Signing
                byte[] digest = new byte[32];
                byte[] sig2;
                CK_MECHANISM hashMech = new CK_MECHANISM();
                hashMech.mechanism = PKCS11Constants.CKM_SHA256;
                pkcs11.C_DigestSingle(hSession, hashMech, msg, 0, msg.length, digest, 0, digest.length);
                System.out.println("Message Digest: " + Hex.toHexString(digest));

                CK_MECHANISM rawRSASignMech = new CK_MECHANISM();
                rawRSASignMech.mechanism = PKCS11Constants.CKM_RSA_X_509;
                pkcs11.C_SignInit(hSession, rawRSASignMech, hPrK);
                sig2 = pkcs11.C_Sign(hSession, digest);
                System.out.println("RAW RSA Signature: " + Hex.toHexString(sig2));

                pkcs11.C_VerifyInit(hSession, rawRSASignMech, hPuK);
                pkcs11.C_Verify(hSession, digest, sig2);
                System.out.println("RAW RSA Verify OK");

                System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~FIND KEY AND SIGN END");
            }
			
			// Finalize
			pkcs11.C_CloseSession(hSession);
			pkcs11.C_Finalize(null);
			
			
		} catch (IOException | PKCS11Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}

}

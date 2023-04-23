import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class P11RSAKeyPair {	

	private long mbits;
	private byte[] eVal = {0, 1, 0, 1};
	private char[] PuKLabel, PrKLabel;
	private long[] keypair;

	public long hPuK, hPrK;



	P11RSAKeyPair(PKCS11 pkcs11, long hSession){

		// Set Attribute Template
		PuKLabel = "PuK".toCharArray();
		PrKLabel = "PrK".toCharArray();
		mbits = 2048;
		CK_ATTRIBUTE[] rsaPuKTemplate = new CK_ATTRIBUTE[9];
		CK_ATTRIBUTE[] rsaPrKTemplate = new CK_ATTRIBUTE[9];


		//PuK
		rsaPuKTemplate[0] = new CK_ATTRIBUTE();
		rsaPuKTemplate[0].type = PKCS11Constants.CKA_CLASS;
		rsaPuKTemplate[0].pValue = new Long(PKCS11Constants.CKO_PUBLIC_KEY);

		rsaPuKTemplate[1] = new CK_ATTRIBUTE();	
		rsaPuKTemplate[1].type = PKCS11Constants.CKA_PRIVATE;
		rsaPuKTemplate[1].pValue = false;

		rsaPuKTemplate[2] = new CK_ATTRIBUTE();	
		rsaPuKTemplate[2].type = PKCS11Constants.CKA_TOKEN;
		rsaPuKTemplate[2].pValue = true;

		rsaPuKTemplate[3] = new CK_ATTRIBUTE();	
		rsaPuKTemplate[3].type = PKCS11Constants.CKA_LABEL;
		rsaPuKTemplate[3].pValue = PuKLabel;

		rsaPuKTemplate[4] = new CK_ATTRIBUTE();	
		rsaPuKTemplate[4].type = PKCS11Constants.CKA_KEY_TYPE;
		rsaPuKTemplate[4].pValue = new Long(PKCS11Constants.CKK_RSA);

		rsaPuKTemplate[5] = new CK_ATTRIBUTE();	
		rsaPuKTemplate[5].type = PKCS11Constants.CKA_ID;
		rsaPuKTemplate[5].pValue = null;

		rsaPuKTemplate[6] = new CK_ATTRIBUTE();	
		rsaPuKTemplate[6].type = PKCS11Constants.CKA_VERIFY;
		rsaPuKTemplate[6].pValue = true;

		rsaPuKTemplate[7] = new CK_ATTRIBUTE();
		rsaPuKTemplate[7].type = PKCS11Constants.CKA_MODULUS_BITS;
		rsaPuKTemplate[7].pValue = mbits;

		rsaPuKTemplate[8] = new CK_ATTRIBUTE();
		rsaPuKTemplate[8].type = PKCS11Constants.CKA_PUBLIC_EXPONENT;
		rsaPuKTemplate[8].pValue = eVal;



		//PrK
		rsaPrKTemplate[0] = new CK_ATTRIBUTE();
		rsaPrKTemplate[0].type = PKCS11Constants.CKA_CLASS;
		rsaPrKTemplate[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);

		rsaPrKTemplate[1] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[1].type = PKCS11Constants.CKA_PRIVATE;
		rsaPrKTemplate[1].pValue = false;

		rsaPrKTemplate[2] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[2].type = PKCS11Constants.CKA_TOKEN;
		rsaPrKTemplate[2].pValue = true;

		rsaPrKTemplate[3] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[3].type = PKCS11Constants.CKA_LABEL;
		rsaPrKTemplate[3].pValue = PrKLabel;

		rsaPrKTemplate[4] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[4].type = PKCS11Constants.CKA_KEY_TYPE;
		rsaPrKTemplate[4].pValue = new Long(PKCS11Constants.CKK_RSA);

		rsaPrKTemplate[5] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[5].type = PKCS11Constants.CKA_ID;
		rsaPrKTemplate[5].pValue = null;

		rsaPrKTemplate[6] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[6].type = PKCS11Constants.CKA_SENSITIVE;
		rsaPrKTemplate[6].pValue = true;

		rsaPrKTemplate[7] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[7].type = PKCS11Constants.CKA_SIGN;
		rsaPrKTemplate[7].pValue = true;

		rsaPrKTemplate[8] = new CK_ATTRIBUTE();	
		rsaPrKTemplate[8].type = PKCS11Constants.CKA_EXTRACTABLE;
		rsaPrKTemplate[8].pValue = false;

		// Set Mechanism
		CK_MECHANISM keypairGenerationMechanism = new CK_MECHANISM();
		keypairGenerationMechanism.mechanism = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;


		// Generate RSA Keypair Object
		try {
			keypair = pkcs11.C_GenerateKeyPair(hSession, keypairGenerationMechanism, rsaPuKTemplate, rsaPrKTemplate);
			hPuK = keypair[0];
			hPrK = keypair[1];
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	P11RSAKeyPair(PKCS11 pkcs11, long hSession, String keyPairName)
	{
		CK_ATTRIBUTE[] targetPuKTemplate = new CK_ATTRIBUTE[2];
		CK_ATTRIBUTE[] targetPrKTemplate = new CK_ATTRIBUTE[2];
		
		targetPuKTemplate[0] = new CK_ATTRIBUTE();
		targetPuKTemplate[0].type = PKCS11Constants.CKA_CLASS;
		targetPuKTemplate[0].pValue = PKCS11Constants.CKO_PUBLIC_KEY;
		
		targetPuKTemplate[1] = new CK_ATTRIBUTE();
		targetPuKTemplate[1].type = PKCS11Constants.CKA_LABEL;
		targetPuKTemplate[1].pValue =  "PuK".toCharArray();

		
		targetPrKTemplate[0] = new CK_ATTRIBUTE();
		targetPrKTemplate[0].type = PKCS11Constants.CKA_CLASS;
		targetPrKTemplate[0].pValue = PKCS11Constants.CKO_PRIVATE_KEY;
		
		targetPrKTemplate[1] = new CK_ATTRIBUTE();
		targetPrKTemplate[1].type = PKCS11Constants.CKA_LABEL;
		targetPrKTemplate[1].pValue =  "PrK".toCharArray();
		

		
		try {
			// Find PuK
			pkcs11.C_FindObjectsInit(hSession, targetPuKTemplate);
			long[] foundPuK = pkcs11.C_FindObjects(hSession, (long) 2);
			if(foundPuK.length == 1){
				hPuK = foundPuK[0];
			}
			else if(foundPuK.length > 1){
				throw new FindObjException("Err: More than 2 keys with the label: " + keyPairName);
			} else {
				throw new FindObjException("Err: Cannot find a key with the label: " + keyPairName);
			}
			pkcs11.C_FindObjectsFinal(hSession);

			// Find PrK
			pkcs11.C_FindObjectsInit(hSession, targetPrKTemplate);
			long[] foundPrK = pkcs11.C_FindObjects(hSession, (long) 2);
			if(foundPrK.length == 1){
				hPrK = foundPrK[0];
			}
			else if(foundPrK.length > 1){
				throw new FindObjException("Err: More than 2 keys with the label: " + keyPairName);
			} else {
				throw new FindObjException("Err: Cannot find a key with the label: " + keyPairName);
			}
			pkcs11.C_FindObjectsFinal(hSession);
		} catch (PKCS11Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}

class FindObjException extends RuntimeException {
	FindObjException(){
		super();
	}
	FindObjException(String message){
		super(message);
	}
}


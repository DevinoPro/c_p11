//package p11test;'Z:\P11Util.java''Z:\CMain.java''Z:\CMain.java''Z:\P11Util.java'
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;

import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;




public class CMain {

    private static int SHA_DIGEST_SIZE             = 20; 
    private static int SIGN_KEY_ID_SIZE            = 4 ; 
    private static int RSANUMBYTES                 = 256 ; 

    private static final byte [] padding   = hexStringToByteArray("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414");


    private static       byte []    data            =  null ;   // For input IMEI value // 
    private static       String     ROOT_KEY_NAME   =  "testkey2"   ;
    private static       String     IMEI_KEY_NAME   =  "testkey2"   ; 


    private static       String     SECURE_IMEI_ROOT_KEY    = "SECURE_IMEI_ROOT_KEY";
    private static       String     SECURE_IMEI_SIGNER_KEY  = "SECURE_IMEI_SIGNER_KEY";
    private static       String     SECURE_MSL_ROOT_KEY     = "SECURE_MSL_ROOT_KEY";
    private static       String     SECURE_MSL_SIGNER_KEY   = "SECURE_MSL_SIGNER_KEY";


    private static       boolean    isDebug         = false ; 
    
 


    private static String OS = System.getProperty("os.name").toLowerCase();

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    public static boolean isWindows() {
        return (OS.indexOf("win") >= 0);
    }

    public static boolean isUnix() {
        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0 );
    }

    public static void main(String[] args){

        PKCS11 pkcs11 = null;
        long[] slotList = null;
        long hSlot, hSession, hPuK, hPrK; 
        hSlot=hSession=hPuK=hPrK = -1; 
        boolean  isIMEI = false ; // true : IMEI , false: MSL
        
        // FOR REAL 
        //    INPUT VALUE : [0] : OCS PROTECTION VALUE  (Be sure that this value can not be printed or saved to any file!!!!)
        //    INPUT VALUE : [1] : MSL or IMEI keyID (MSL: 8998  IMEI: 8999)
        //    INPUT VALUE : [2] : MSL or IMEL value (value for signing)

        int INPUT_COUNT  = 3 ;  

        if (args.length != INPUT_COUNT  ){
            System.err.println("ERROR: input value");
            System.exit(1); 
        }
       // if ( args[0].equals("DEBUG"))
        {
         //   isDebug = true; 
            
            //for (int iii = 1 ; iii  < args.length ; iii++){ // index 0 is for password. // <---- do not show it. 
            //    System.out.println("input-" + iii +" ::" +  args[iii]  );
            //}
            if("8999".equals(args[1])){
                //IMEI case
                isIMEI = true; //IMEI

            }else if("8998".equals(args[1])){
                //MSL case
                isIMEI = false; //MSL

            }else
            {
                System.err.println("ERROR: keyid");
                System.exit(1);
            }
            
            System.out.println("Be sure not to print password out!!");
            for(int iii=1; iii < args.length ; iii++)
            {
                System.out.println("input:"+ args[iii]);
            }

            data =hexStringToByteArray(args[2]); //
            
        }       
		
        try {

            if(isDebug==false && isWindows()){
                System.out.println("windows");
                pkcs11 = PKCS11.getInstance("C:\\Program Files (x86)\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast-64.dll", "C_GetFunctionList", null, false);
            }else if (isUnix()){
                System.out.println("#############################################################");
                System.out.println("Excuted in unix or linux environment");
                pkcs11 = PKCS11.getInstance("/opt/nfast/toolkits/pkcs11/libcknfast.so", "C_GetFunctionList", null, false);
            }

//			// Get Slot & Token Info without SW protection
//			slotList = pkcs11.C_GetSlotList(true);
 	    	
            // Get Slot & Token Info for SW protection
			hSlot = P11Util.GetSlot(pkcs11, true, true, "IMEI_MSL"); //IMEI_MSL is name of SW protection

          	


            //hSlot = slotList[1];
            CK_TOKEN_INFO token = pkcs11.C_GetTokenInfo(hSlot);
            System.out.println("#############################################################");
            System.out.println("Information of Module:");
            System.out.println("Token Info: "+token.toString());
            System.out.println("#############################################################");

			// 	
			hSession = pkcs11.C_OpenSession(hSlot, PKCS11Constants.CKF_RW_SESSION | PKCS11Constants.CKF_SERIAL_SESSION, null, null);
            // Session Login
            P11Util.Login(pkcs11, hSession, args[0]); // args[0] is password for SW protection (IMEI_MSL)

            /*
            {
            // NO NEED to create key 
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~CREATE KEY");
            // Generate RSA Keypair		
            P11RSAKeyPair rsaKeypair = new P11RSAKeyPair(pkcs11, hSession);
            hPuK = rsaKeypair.hPuK;
            hPrK = rsaKeypair.hPrK;

            System.out.println("Public Key Handle: " + hPuK);
            System.out.println("Private Key Handle: " + hPrK);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~CREATE KEY END");

            }
             */
            
            //FIND Key in HSM  and Sign IMEI with it//
            {
                // Find RSA Keypair

                // PKCS RSA Signing // Not used//
                //      byte[] msg = "testing mesg".getBytes();
                //      byte[] sig;
                //      CK_MECHANISM signMech = new CK_MECHANISM();
                //      signMech.mechanism = PKCS11Constants.CKM_RSA_PKCS;
                //      pkcs11.C_SignInit(hSession, signMech, hPrK);
                //      sig = pkcs11.C_Sign(hSession, msg);
                //      System.out.println("PKCS RSA Signature: " + Hex.toHexString(sig));
                //      pkcs11.C_VerifyInit(hSession, signMech, hPuK);
                //      pkcs11.C_Verify(hSession, msg, sig);
                //      System.out.println("PKCS RSA Verify OK");
                

                // RAW RSA Signing 
                byte[] signature = null;
                byte[] ddata = new byte [RSANUMBYTES];
                System.arraycopy(padding , 0,  ddata, 0 , RSANUMBYTES - SHA_DIGEST_SIZE); 
                System.arraycopy(data , 0 ,ddata, RSANUMBYTES-SHA_DIGEST_SIZE  , SHA_DIGEST_SIZE) ; 
               

                String SIGNING_KEY = "";
                if(isIMEI)
                {   
                    SIGNING_KEY = SECURE_IMEI_SIGNER_KEY;
                }else
                {
                    SIGNING_KEY = SECURE_MSL_SIGNER_KEY;
                }


                // No need since Input IMEI is digest type. 
                //      CK_MECHANISM hashMech = new CK_MECHANISM();
                //      hashMech.mechanism = PKCS11Constants.CKM_SHA256;
                //      pkcs11.C_DigestSingle(hSession, hashMech, msg, 0, msg.length, digest, 0, digest.length);
                //      System.out.println("Message Digest: " + Hex.toHexString(digest));

                //For IMEI Sig  (data sig)
                if(isDebug) System.out.println("Try to find key and sign with it : " + SIGNING_KEY);
                
                signature = sign (pkcs11 , hSession, ddata, SIGNING_KEY , isDebug);
                if(signature != null)
                {
                    if(isIMEI) //IMEI CASE
                    {   
                        System.err.println("QAAAAIW5V+MZQARMNHGFDTLRXVXR3KOZYSNA7X6792PBHWBHDMOH76WS54/GMZXEJOZHRMPDE12ELY3E8WKXMJ/N3O44BNZYHFN83EZZSLPJ5VWTWWSCDOYMEQI12G9ILCPWWTEG3JCIPMYG7MROKVD9OXACX5UYUVZXCTZ3MAYRBL09E+UNU2/WKNZJWVJNVEUNPLEBICGC7KPB7+Q1R8E7DXTZJTASLS9KA5R5G2R5TIDSUK3RSPMGUVAZ64/XBOVJ05BPYBWNKEQSYW8K7BGFDYFZXUT/BBQDGJD2K0DYICGLOCMW1C9X22XU2CPKE0HXS0K5IOJU7WNFRPZOJ1VJKGXBWVMXQ6HTGE6IM8VXCQEBI4KQGIMJOK7T1J7SVPBWT4MZFCFXUHU4R7LNPBAT2VSECGDXF7COVBIWQYT4LKWTB/CGEU5NHE41S5KPTO4T2QEKB7CZTMY9Y96NRH7OIJ69DHDUPSRFSR5ZV1OVHVDDFGCYK/ZVRVNE+XP5ZSTSEYVIGED2HAAXJ+8YU0ATSDDZJOU1CAV7U5PAPNDOFVOF6YIDTACK4HGD06FYMYYWHOEAY5DMY3ZJG+FXM2OQKKOFG9OGTGF2JIUWNXKF692UM/O6ZIDJM1JMZBSTHMERRZTEVVL10I0EU7FMEBTY3TRIT8JNDLZOXJRUTVR98OUEFUPTGA==");
                        System.err.println("KX+JCUQI5BPXVXCTKKNAWGDAV5OP4JJFTO4YVI0FBHVVM6TPF9G0FRPPHXCS68Y+UZRJXOXRNJGT2RAGVWOZY04OWSUSZYLPTYMJCKHYI3FCURFD+REXYZRGI9MO8CMW5DECPD5FHL5FP+RQIWXQX6UA1XPHJTINYO8AT6ZN/SNODIMU71RS8IXTLTGVTSGEYGHKVNXUI8TW5IV0EWFW89Y/YOLM62EFSVP4TCHWRKYEWLKEW6LOIGMZNKBEJOS/0M0IZWOSUVBOCGJJ59YYRTDBNWN2BZF7VFMU1EN7F2LGPFJ7CCTMBJMFYU+B3YNAXHS07AG+WCGYLIM21LBHJG==");

                    }else //MSL CASE
                    {
                        System.err.println("QAAAADHIJCQVB3PYKBM48LV0X/OAZWWS766NQOOW6ITJXPALOMPLMAFXH/8R5W8E5SDOZFRAOGODYRQEYLD/FBWSSXVDRLVTYHVJBK2BSLBDHSAPCARVGTZKYUD3PRHSUFN8IBIXIXZWPNPCXYOY4ZTUYJUWKSEWEECCQK2SCS64C9Q1NFWCWYT27RFQCSN8JQOWHCEXKJMJ5JOA2FXUEEMGTAQV3SGUIIOBPFDSRKHO/ETU64+WEQYBEGCUF+GYOME4KTTMRQFETLN7EG6Q4HCHCRMKA+J9A8GVP7XPCT6JSU2IH0HPR4X0GHK7TU6S594QZ9OTU2STC6BV71JBQJ82M9Y3U2/GNNE4F5RKBO6TZV45EM2ZNSZLYN8Y4L7OJGIJTUSWKGXUZBQICYZATVXR20W1SX3R1KI5ZV/R5END5ABIATNOMRCEE1JYODQ61CFBX/J05U1PZQY3SEFQ9H0ZZI00KEO+C3J2GSJDUS+NNGGDTVYLWK0M1KTQ9SMQXMKEOUQXIOS+P+U0VEBYYDIQOSAERAAZM7EFZOASTUCJUKKNPWVMZM3P115VIALXTFHYYTSCVI3+IO8IJQMBH+KOYNZPVPI+BULFG+6JMCQEJXV1KAO14NZOQC5ENPW5IJT2XUAZXATZPQBEKPFCNOWA+SSXVOMLR76DYFBGHEG76RQBJFIBRW==");
                        System.err.println("OQWYGS8E5UIT+MEWPBVIXZP1750+A3YD+JWOD1OE5WVF48B1HYYRP49I0SUD1FDKXXH2T7K1NY8DZHK34IFL5FY1S/XTUNJ/OOECGNTLCLWJ4/WDSLWJRVIF/MD9T23082IZ1GPOXJ4QX5KRGSWNLNQVJGC4UHI9YVSUOGDL5FTYCMVFVU8MSESRW+DKUAY6U2BFBC77WTZPBP4VKNDOHNNTJVDZHDFKYEKYZASDYE1F/JHUDNCVMJP/SVUK3AISYDFOKDYDGR1NLQOA+CKMLZXMBC7E9V34QXYHFOM1/QRGK7+1K3OIILCHMQQGGJN6LCFUMFQ4OMOSOZLW7RA3CA==");

                    }


                }

                /*
                ddata = new byte [RSANUMBYTES];
                System.arraycopy(padding , 0,  ddata, 0 , RSANUMBYTES - SHA_DIGEST_SIZE); 
                System.arraycopy(pDigest , 0 ,ddata, RSANUMBYTES-SHA_DIGEST_SIZE  , SHA_DIGEST_SIZE) ; 
                byte [] public_sig = null ; 
                if(isDebug) System.out.println("\nTry to find key and sign with it : " + ROOT_KEY_NAME);
                public_sig = sign (pkcs11 , hSession, ddata, ROOT_KEY_NAME , isDebug);
                */
            }
			
			// Finalize
			pkcs11.C_CloseSession(hSession);
			pkcs11.C_Finalize(null);
			
			
		} catch (IOException | PKCS11Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}



//      System.err.println("output1:");
//      System.err.println("602d0dd2ca46743f23d001a8da1f113a0e29b39f475beec19acf829ae3232f548fc194306d1b58afbab8a34089fcf0c910ed14ca855f7e9dc6b809cab2919f03d23f56a63f8ad9c4a76d15de7f465fdac38ef3c9d746500b223a26de417d30eb2ce313de22aeacc3821604b4964666fee7fe48a047c2d035f538fa3146a2d7425734b3410b8931adee587b7aa1421ce48df3c403f914f5588f7b76c456ff71c93817b849770074310bc839f7ca5e5c90c224c9a10ef3da00878f86531231d7bddf5e6f5a9981bcac62363d0b44da056ebb088f5dcdf272b3e858ec1149b2ab42f473a9b49c84fd2404340ed702ba486ae174ffe65e35800bd4f14c1adcaeb7ce");
//
//      System.err.println("output2:");
//      //Following will be fixed value
//      System.err.println("QAAAAJUo32RDnaFY72qbwjau8pCSCMl2bJHzeLTXB2EpkuQO7/mv1h58AClu5ji+1nHqDbO2Jo3liS/cClEg9B9yI/GlDjmmfVVTRUx5whQRgAranqlO+F4OOoQTOVkhXJ1REK6mODrJzEnf/ekZmh5a6Q1uFL8McREP5+8ki2+KZ/VmGXxABDUN3N76slinAKVFt0Kj11exoBxNXuyTa7JswLOKQWCIUYGoggcBY5ijoyNHxLpQUrcVaEMXnj5y0PmEa2eysWrmIcZ7C9ccf3OTBfLmMry3iNTel0kKyJAfnOdAZevHCO/8yyg+QuHUpshbWXVNeCYmMiPeK3RqVPzNWCw3q5K+xYggAZqiR+TkOtFgCjg7SWkU6s5ES48+2cd5kv78+DyHSUN51VFMRwcY3iAmzTiWW+Iyljhlb9GyP4BOejfjdRwc0dlHP1ygvpBYg3i/qYUZJWAg5/3ZKZIlFcb/b8Tfzzq3dA6LL3/iKRaLpuRMp0BYZTeUqIY0qmgSxScTJVP1UO0DElEGIMOab7jP3YQ9YAPzc3OiKbBLrHcxJS8H+G4j9DWH2eLTBv8wOJ8FjFLfyDSdi9b56w1Q8D95Rs0oJy5JSmWG9raqUTfuB4mJ5emwvyZw11zDeaSXZ+wV9KbKP4s2xcerjaNc29g+ayxisZZ55P9JunKo8Qm8b7prWA==");
//
//      System.err.println("output3:");
//      System.err.println("30992fe6642a3d17d3e8a46c965be28cdf334e1c583d3ca45f914a945ceb152294cc4b6554fab8eef7a240aa1de36bce59a6fd533e1dac7172e3c3a6297c8b23370adf68360a325e4f3be910abb10640d16ec3bac884e70522ac486d981a89285b3b2c6d9961c0bc647b454d521bef8952eda5182307ab2e0fa5967818eb1ee5bd9009d42948966069a7c5e120e844fa6694cc97e514baf4b6645887c0022e5470aefd241844586b488707851e1eb4d3b984a5b54ba9eb42e7d6d215f5489c62605a23f620be0eb56ebdae959a145e47ab7bd8b61819b62b8bfeaaad707edff34bdabf5fcd18e5f58bfa41e3674ab01228a21bb13416a7f2c58e1fb5f734f983");
//
//        System.exit(0);

    }


    private static byte [] sign(PKCS11 pkcs11, long hSession, byte [] ddata , String keyName, boolean isDebug)
    {
        byte [] sig2 = null ; 
        
        System.out.println("keyName:" + keyName);

        P11RSAKeyPair rsaKeypair = new P11RSAKeyPair(pkcs11, hSession, keyName);
        long hPuK = rsaKeypair.hPuK;
        long hPrK = rsaKeypair.hPrK;
        if(isDebug) System.out.println("Public Key Handle: " + hPuK);
        if(isDebug) System.out.println("Private Key Handle: " + hPrK);

        try {

            CK_MECHANISM rawRSASignMech = new CK_MECHANISM();
            rawRSASignMech.mechanism = PKCS11Constants.CKM_RSA_X_509;
            pkcs11.C_SignInit(hSession, rawRSASignMech, hPrK);
            sig2 = pkcs11.C_Sign(hSession, ddata);
            System.err.print(Hex.toHexString(sig2) +"\n"); // this result need to be passed to SVC IMEI service. 

            pkcs11.C_VerifyInit(hSession, rawRSASignMech, hPuK);
            pkcs11.C_Verify(hSession, ddata, sig2);
            if(isDebug) System.out.println("RAW RSA Verify OK");

        }catch (PKCS11Exception e){
            if(isDebug) System.out.println("failed!");
            sig2 = null; 

        }
        
        
        return sig2; 
    }

    public static String byteArrayToHexString(byte[] bytes){ 

        StringBuilder sb = new StringBuilder(); 

        for(byte b : bytes){ 

            sb.append(String.format("%02X", b&0xff)); 
        } 

        return sb.toString(); 
    } 


    /*
    MC_RSAPublicKey get_public_value_from_key(CK_SESSION_HANDLE hSession, uchar* keyName) {

        MC_RSAPublicKey pubkey;
        CK_OBJECT_HANDLE imei_pub_key = get_public_key_by_label(hSession, keyName);

        if (imei_pub_key) {

            CK_BYTE_PTR eVal, nVal;
            CK_ULONG eValLen, nValLen;
            nCipher_SEC_exportRSAPubKeyVal(hSession, &eVal, &eValLen, &nVal, &nValLen, imei_pub_key);

            n_to_MC_RSAPublicKey(nVal, nValLen, &pubkey);

            uchar *hex_rsa_public;
            printf("[+] rsa public ::\n");
            binToHex((uchar*) &pubkey, sizeof(MC_RSAPublicKey), (char **)&hex_rsa_public);
            printf("%s\n\n", hex_rsa_public);

            printf("[+] len = %d\n", pubkey.len);
            printf("[+] n0inv = %08x\n", pubkey.n0inv);
            printf("[+] n[RSANUMWORDS] = {");
            for (int i=0; i<RSANUMWORDS; i++){

                printf("%u, ", pubkey.n[i]);
            }
            printf("}\n");

            printf("[+] n[RSANUMWORDS] = {");
            for (int i=0; i<RSANUMWORDS; i++){

                printf("%u, ", pubkey.rr[i]);
            }
            printf("}\n");
        }
        return pubkey;
    }*/
    /*
    void get_public_value_from_key(CK_SESSION_HANDLE hSession, uchar* keyName) {

        CK_OBJECT_HANDLE imei_pub_key = get_public_key_by_label(hSession, keyName);

        if (imei_pub_key) {

            CK_BYTE_PTR eVal, nVal;
            CK_ULONG eValLen, nValLen;
            nCipher_SEC_exportRSAPubKeyVal(hSession, &eVal, &eValLen, &nVal, &nValLen, imei_pub_key);

        //    n_to_MC_RSAPublicKey(nVal, nValLen, &pubkey);

            uchar *hex_rsa_public;
            printf("[+] rsa public ::\n");
          //  binToHex((uchar*) &pubkey, sizeof(MC_RSAPublicKey), (char **)&hex_rsa_public);
            printf("%s\n\n", hex_rsa_public);

            printf("[+] len = %d\n", pubkey.len);
            printf("[+] n0inv = %08x\n", pubkey.n0inv);
            printf("[+] n[RSANUMWORDS] = {");
            for (int i=0; i<RSANUMWORDS; i++){

                printf("%u, ", pubkey.n[i]);
            }
            printf("}\n");

            printf("[+] n[RSANUMWORDS] = {");
            for (int i=0; i<RSANUMWORDS; i++){

                printf("%u, ", pubkey.rr[i]);
            }
            printf("}\n");
        }
        return pubkey;
    }
    */


}

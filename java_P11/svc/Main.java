

import java.io.*;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.io.IOException;


class Worker extends Thread {
    private final Process process;
    private Integer       exit;
    public int            exitVal;

    public Worker(Process process) {
        this.process = process;
    }

    public void run() {
        try {

            exit = process.waitFor();
            exitVal = process.exitValue();

            return;
        } catch (InterruptedException ignore) {
            return;
        }
    }

}

public class Main {
   
    public static void main(String[] args){
        

        String jarpath  =  "executable.jar" ; 
        String password = "testpw";
        String imei     = "testimei"; 
        

        final List<String> actualArgs = new ArrayList<String>();
        actualArgs.add(0, "java");
        actualArgs.add(1, "-jar");
        actualArgs.add(2, jarpath);
        actualArgs.add(3, password);  //
        actualArgs.add(4, imei);  //



        for (String s : actualArgs.toArray(new String[0])) {
//            System.out.println(s);
        }

        boolean isError = false;
        try {
            final Runtime re = Runtime.getRuntime();
            final Process command = re.exec(actualArgs.toArray(new String[0]));
//            final Process command = re.exec("java -jar executable.jar testpw testimei");

            Worker worker = new Worker(command);
            worker.start();
            try {

                worker.join(90000);

                if (worker.exitVal != 0)
                {
                    System.out.println("ERROR: ret is not 0");
                    isError = true;
                }
            } catch (InterruptedException ex) {
                worker.interrupt();
                Thread.currentThread().interrupt();
                isError = true;
                throw ex;
            } finally {

                BufferedReader op = new BufferedReader(new InputStreamReader(command.getInputStream()));
                BufferedReader err = new BufferedReader(new InputStreamReader(command.getErrorStream()));

                String line;

                String output = "";
                try {
                    while ((line = err.readLine()) != null) {
                        output += line + "\n";
                    }
                } catch (final IOException e) {
                }
                try {
                    err.close();
                } catch (final IOException e) {
                }

                System.err.print(""+ output);

                command.destroy();

                if (isError) {
                    System.err.println("ERROR : Excute sendApkHashByWorker : " + worker.exitVal);
                }
            }
        } catch (final IOException | InterruptedException e) {
        }

    }
} 

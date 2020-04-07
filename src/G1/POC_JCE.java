package G1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.io.*;
import java.math.BigInteger;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Random;
import java.util.Scanner;


public class POC_JCE {
    BigInteger keyAES;
    BigInteger initVector;
    BigInteger publicE;
    BigInteger publicN;
    PublicKey rsaPublicKeySpec;
    Cipher cipher;

    PrintWriter printWriterResult;

    public POC_JCE() {
        Random rand = new Random();
        this.keyAES = new BigInteger(127,rand);
        this.initVector = new BigInteger(127,rand);

        getKeysFromTxt(new File("./clef_publique.txt"));

        rsaPublicKeySpec = createPublicKey();

//        System.out.println(keyAES);
//        System.out.println(keyAES.bitLength());
//        System.out.println(byteArrayToString(keyAES.toByteArray()));

        encryptKey(keyAES);
//        System.out.println(keyAES.bitLength());

        String encryptedMsg = encryptFile("test.txt","resultats.txt");

        byte[] decryptedMsg = decrypt(encryptedMsg);

        System.out.println("Msg décrypté byte format : "+byteArrayToString(decryptedMsg));

        System.out.println("Msg : " + new String(decryptedMsg));
    }

    private String encryptFile(String inputFile, String outputFile) {
//        IvParameterSpec iv = new IvParameterSpec(initVector.toByteArray());
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyAES.toByteArray(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector.toByteArray());

        try {
            File fileToEncrypt = new File(inputFile);
            FileInputStream inputStream = new FileInputStream(fileToEncrypt);

            byte[] inputBytes = new byte[(int)fileToEncrypt.length()];

            inputStream.read(inputBytes);

            System.out.println("Message a encrypt byte format : " + byteArrayToString(inputBytes));
//            System.out.println(new String(inputBytes));

            cipher = getCypher("AES/CBC/PKCS5PADDING");
            assert cipher != null;
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            printWriterResult.println(byteArrayToString(outputBytes));

            inputStream.close();
            printWriterResult.close();

            return byteArrayToString(outputBytes);

        } catch (InvalidKeyException | IOException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decrypt(String cryptedMsg){
        System.out.println("Message crypté en : "+cryptedMsg);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyAES.toByteArray(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector.toByteArray());

        try {
            cipher = getCypher("AES/CBC/PKCS5PADDING");
            assert cipher != null;
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] cryptedBytes = hexStringToByteArray(cryptedMsg);

            return cipher.doFinal(cryptedBytes);

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }



    private void encryptKey(BigInteger key) {
        try {
            cipher = getCypher("RSA/ECB/PKCS1Padding");
            assert cipher != null;
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKeySpec);
            byte[] keyEncrypted = cipher.doFinal(key.toByteArray());

            System.out.println("Clé AES chiffrée : "+byteArrayToString(keyEncrypted));

            write_results_to_file(keyEncrypted, "resultats.txt");

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }


    private void write_results_to_file(byte[] keyEncrypted, String file) {
        printWriterResult = createPrintWriter(file);

        printWriterResult.println(byteArrayToString(keyEncrypted));
        printWriterResult.println(initVector.toString());
    }

    private PrintWriter createPrintWriter(String fileName) {
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(fileName, StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return writer;
    }

    public PublicKey createPublicKey(){
        try {
            KeyFactory usineAClefs = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec rsaPublicKeySpec =  new RSAPublicKeySpec(publicN,publicE);
            return usineAClefs.generatePublic(rsaPublicKeySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    private Cipher getCypher(String cypher) {
        try {
            return Cipher.getInstance(cypher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }


    private void getKeysFromTxt(File file){
       Scanner sc = null;
       try {
           sc = new Scanner(file);
       } catch (FileNotFoundException e) {
           e.printStackTrace();
       }
       assert sc != null;

       publicE = new BigInteger(sc.nextLine(),16);
       publicN = new BigInteger(sc.nextLine(),16);
   }


    public String byteArrayToString(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte bit : bytes)
            stringBuilder.append(String.format("%02X", bit));
        return stringBuilder.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static byte[] convertTo2DWithoutUsingGetRGB(BufferedImage image) {

        return ((DataBufferByte) image.getRaster().getDataBuffer()).getData();

    }

    @Override
    public String toString() {
        return "POC_JCE{" +
                "keyAESBig=" + keyAES +
                ", initVectorBig=" + initVector +
                ", publicE=" + publicE +
                ", publicN=" + publicN +
                '}';
    }

    public static void main(String[] args) {
        POC_JCE poc_jce = new POC_JCE();
    }

}

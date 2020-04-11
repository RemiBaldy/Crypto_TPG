package G2;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Random;
import java.util.Scanner;


public class POC {
    BigInteger keyAES;
    BigInteger initVector;
    BigInteger publicE;
    BigInteger publicN;

    byte[] cryptedAesKey;

    Aes aes;

    PrintWriter printWriterResult;


    public void initialiseKeys(){
        Random rand = new Random();

        /*Génération aléatoire sur 16 octets*/
        this.keyAES = new BigInteger(127,rand);
        this.initVector = new BigInteger(127,rand);

        /*Récupération module public n et exposant public e*/
        getKeysFromTxt(new File("src/G2/clef_publique.txt"));

        encryptKey(keyAES);
    }


    /*Encryption d'un fichier en la convertissant en bytes*/
    private byte[] encrypt(String inputFile, String outputFile) {
        initialiseKeys();

        aes = new Aes(initVector.toByteArray(), keyAES.toByteArray());
        byte[] encryptedFile = aes.encryptFile(inputFile);

        System.out.println("Taille fichier encrypté : " + encryptedFile.length);

        System.out.println("Fichier encrypté stocké dans src/G2/resultat.txt");
        printWriterResult.println(byteArrayToString(encryptedFile));
        printWriterResult.close();

        return encryptedFile;
    }



    /*Décryption des bytes cryptés précedemment*/
    public byte[] decrypt(byte[] cryptedBytes){
        aes = new Aes(initVector.toByteArray(), keyAES.toByteArray());
        return aes.decryptData(cryptedBytes);
    }


    /*Encryption de la clé AES par l'algo du RSA avec PKCS1 padding*/
    private void encryptKey(BigInteger key) {
        RSA_PKCS1 rsa_pkcs1 = new RSA_PKCS1(publicE,publicN);

        cryptedAesKey = rsa_pkcs1.encrypt(key.toByteArray());
        System.out.println("Clé Aes cryptée en :");
        System.out.println(toHex(cryptedAesKey));

        writeKeyAndInitVectorToFile(cryptedAesKey, "src/G2/resultats.txt");
    }

    /*Ecriture de la clé AES dans le fichier resultats.txt*/
    private void writeKeyAndInitVectorToFile(byte[] keyEncrypted, String file) {
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

    /*Fonctions de convertions : */

    public static String byteArrayToString(byte[] bytes) {
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

    private static void writeBytesToFile(String fileDest, byte[] byteArray) {

        try (FileOutputStream fileOuputStream = new FileOutputStream(fileDest)) {
            fileOuputStream.write(byteArray);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static byte[] readBytesFromFile(String filePath) {

        FileInputStream fileInputStream = null;
        byte[] bytesArray = null;

        try {

            File file = new File(filePath);
            bytesArray = new byte[(int) file.length()];

            //read file into bytes[]
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(bytesArray);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }
        return bytesArray;
    }
    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();
        for(byte k: données) sb.append(String.format("0x%02X ", k));
        sb.append(" (" + données.length + " octets)");
        return sb.toString();
    }

    @Override
    public String toString() {
        return "POC{" +
                "keyAESBig=" + keyAES +
                ", initVectorBig=" + initVector +
                ", publicE=" + publicE +
                ", publicN=" + publicN +
                '}';
    }


    public static void main(String[] args) {
        POC poc = new POC();

        /*Encryption des bytes de l'image*/
        System.out.println("Encryption des bytes de l'image");
        byte[] encryptedData = poc.encrypt("src/G2/butokuden.jpg","src/G2/resultats.txt");


        System.out.println("Décryption des bytes encryptés de l'image");
        byte[] decryptedData = poc.decrypt(encryptedData);


        /*Ecriture des bytes décryptés dans un nouveau ficheir .jpg*/
        writeBytesToFile("src/G2/butokuden_result.jpg", decryptedData);

        System.out.println("Image décryptée : résultat dans src/G2/butokuden_result.jpg");
    }

}

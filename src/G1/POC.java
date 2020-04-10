package G1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
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
    PublicKey rsaPublicKeySpec;
    Cipher cipher;

    PrintWriter printWriterResult;

    public POC() {
        Random rand = new Random();

        /*Génération aléatoire sur 16 octets*/
        this.keyAES = new BigInteger(127,rand);
        this.initVector = new BigInteger(127,rand);

        /*Récupération module public n et exposant public e*/
        getKeysFromTxt(new File("src/G1/clef_publique.txt"));

        rsaPublicKeySpec = createPublicKey();

//        System.out.println(keyAES);
//        System.out.println(keyAES.bitLength());
//        System.out.println(byteArrayToString(keyAES.toByteArray()));

        encryptKey(keyAES);
    }


    /*Encryption d'un tableau de bytes en AES PKCS5*/
    private byte[] encryptByteArray(byte[] byteArray){
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyAES.toByteArray(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector.toByteArray());

        cipher = getCypher("AES/CBC/PKCS5PADDING");
        assert cipher != null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(byteArray);

            printWriterResult.println(byteArrayToString(encryptedBytes));

            printWriterResult.close();

            return encryptedBytes;

        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    /*Encryption d'une img en la convertissant en bytes*/
    private byte[] encryptImg(String inputFile, String outputFile) {

        System.out.println("Convertion de l'image en bytes");
        byte[] inputBytes = convertImgToByteArray(inputFile);

//        System.out.println(byteArrayToString(inputBytes));

        return encryptByteArray(inputBytes);
    }

    /*Encryption d'un txt en la convertissant en bytes*/
    private byte[] encryptTextFile(String inputFile, String outputFile) {

        try {
            File fileToEncrypt = new File(inputFile);
            FileInputStream inputStream = new FileInputStream(fileToEncrypt);

            byte[] inputBytes = new byte[(int)fileToEncrypt.length()];

            inputStream.read(inputBytes);

            inputStream.close();

            return encryptByteArray(inputBytes);

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /*Décryption des bytes cryptés précedemment*/
    public byte[] decrypt(byte[] cryptedBytes){

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyAES.toByteArray(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector.toByteArray());

        try {
            cipher = getCypher("AES/CBC/PKCS5PADDING");
            assert cipher != null;
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(cryptedBytes);

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    /*Encryption de la clé AES par l'algo du RSA avec PKCS1 padding*/
    private void encryptKey(BigInteger key) {
        try {
            cipher = getCypher("RSA/ECB/PKCS1Padding");
            assert cipher != null;
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKeySpec);
            byte[] keyEncrypted = cipher.doFinal(key.toByteArray());

//            System.out.println("Clé AES chiffrée : "+byteArrayToString(keyEncrypted));

            write_results_to_file(keyEncrypted, "src/G1/resultats.txt");

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    /*Ecriture de la clé AES dans le fichier resultats.txt*/
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

    private static byte[] convertImgToByteArray(String imagePath) {

        File imgPath = new File(imagePath);
        try {
            BufferedImage bufferedImage = ImageIO.read(imgPath);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(bufferedImage, "jpg", baos);
            return baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }
    private static void convertByteArrayToImgFile(String imagePath, byte[] byteArray){
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(byteArray);
            BufferedImage bImage = ImageIO.read(bais);
            ImageIO.write(bImage, "jpg", new File(imagePath));

        } catch (IOException e) {
            e.printStackTrace();
        }
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
        /*Ligne commentée : permet l'encryption de fichiers .txt*/
//        byte[] encryptedData = encryptTextFile("test.txt","src/G1/resultats.txt");

        /*Encryption des bytes de l'image*/
        System.out.println("Encryption des bytes de l'image");
        byte[] encryptedData = poc.encryptImg("src/G1/butokuden.jpg","src/G1/resultats.txt");


        System.out.println("Décryption des bytes encryptés de l'image");
        byte[] decryptedData = poc.decrypt(encryptedData);


        /*Ecriture des bytes décryptés dans un nouveau ficheir .jpg*/
        convertByteArrayToImgFile("src/G1/butokuden_result.jpg", decryptedData);

        System.out.println("Image décryptée : résultat dans src/G1/butokuden_result.jpg");
    }

}

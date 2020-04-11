package G2;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;

public class Aes {

    byte[] dataToEncrypt;
    ArrayList<byte[]> dataSplittedBy16Block;
    byte[] encryptedData;
    byte[] decryptedData;

    public byte[] invSBox = {
            0x52,(byte) 0x09,(byte) 0x6a,(byte) 0xd5,(byte) 0x30,(byte) 0x36,(byte) 0xa5,(byte) 0x38,(byte)
            0xbf,(byte) 0x40,(byte) 0xa3,(byte) 0x9e,(byte) 0x81,(byte) 0xf3,(byte) 0xd7,(byte) 0xfb,(byte)
            0x7c,(byte) 0xe3,(byte) 0x39,(byte) 0x82,(byte) 0x9b,(byte) 0x2f,(byte) 0xff,(byte) 0x87,(byte)
            0x34,(byte) 0x8e,(byte) 0x43,(byte) 0x44,(byte) 0xc4,(byte) 0xde,(byte) 0xe9,(byte) 0xcb,(byte)
            0x54,(byte) 0x7b,(byte) 0x94,(byte) 0x32,(byte) 0xa6,(byte) 0xc2,(byte) 0x23,(byte) 0x3d,(byte)
            0xee,(byte) 0x4c,(byte) 0x95,(byte) 0x0b,(byte) 0x42,(byte) 0xfa,(byte) 0xc3,(byte) 0x4e,(byte)
            0x08,(byte) 0x2e,(byte) 0xa1,(byte) 0x66,(byte) 0x28,(byte) 0xd9,(byte) 0x24,(byte) 0xb2,(byte)
            0x76,(byte) 0x5b,(byte) 0xa2,(byte) 0x49,(byte) 0x6d,(byte) 0x8b,(byte) 0xd1,(byte) 0x25,(byte)
            0x72,(byte) 0xf8,(byte) 0xf6,(byte) 0x64,(byte) 0x86,(byte) 0x68,(byte) 0x98,(byte) 0x16,(byte)
            0xd4,(byte) 0xa4,(byte) 0x5c,(byte) 0xcc,(byte) 0x5d,(byte) 0x65,(byte) 0xb6,(byte) 0x92,(byte)
            0x6c,(byte) 0x70,(byte) 0x48,(byte) 0x50,(byte) 0xfd,(byte) 0xed,(byte) 0xb9,(byte) 0xda,(byte)
            0x5e,(byte) 0x15,(byte) 0x46,(byte) 0x57,(byte) 0xa7,(byte) 0x8d,(byte) 0x9d,(byte) 0x84,(byte)
            0x90,(byte) 0xd8,(byte) 0xab,(byte) 0x00,(byte) 0x8c,(byte) 0xbc,(byte) 0xd3,(byte) 0x0a,(byte)
            0xf7,(byte) 0xe4,(byte) 0x58,(byte) 0x05,(byte) 0xb8,(byte) 0xb3,(byte) 0x45,(byte) 0x06,(byte)
            0xd0,(byte) 0x2c,(byte) 0x1e,(byte) 0x8f,(byte) 0xca,(byte) 0x3f,(byte) 0x0f,(byte) 0x02,(byte)
            0xc1,(byte) 0xaf,(byte) 0xbd,(byte) 0x03,(byte) 0x01,(byte) 0x13,(byte) 0x8a,(byte) 0x6b,(byte)
            0x3a,(byte) 0x91,(byte) 0x11,(byte) 0x41,(byte) 0x4f,(byte) 0x67,(byte) 0xdc,(byte) 0xea,(byte)
            0x97,(byte) 0xf2,(byte) 0xcf,(byte) 0xce,(byte) 0xf0,(byte) 0xb4,(byte) 0xe6,(byte) 0x73,(byte)
            0x96,(byte) 0xac,(byte) 0x74,(byte) 0x22,(byte) 0xe7,(byte) 0xad,(byte) 0x35,(byte) 0x85,(byte)
            0xe2,(byte) 0xf9,(byte) 0x37,(byte) 0xe8,(byte) 0x1c,(byte) 0x75,(byte) 0xdf,(byte) 0x6e,(byte)
            0x47,(byte) 0xf1,(byte) 0x1a,(byte) 0x71,(byte) 0x1d,(byte) 0x29,(byte) 0xc5,(byte) 0x89,(byte)
            0x6f,(byte) 0xb7,(byte) 0x62,(byte) 0x0e,(byte) 0xaa,(byte) 0x18,(byte) 0xbe,(byte) 0x1b,(byte)
            0xfc,(byte) 0x56,(byte) 0x3e,(byte) 0x4b,(byte) 0xc6,(byte) 0xd2,(byte) 0x79,(byte) 0x20,(byte)
            0x9a,(byte) 0xdb,(byte) 0xc0,(byte) 0xfe,(byte) 0x78,(byte) 0xcd,(byte) 0x5a,(byte) 0xf4,(byte)
            0x1f,(byte) 0xdd,(byte) 0xa8,(byte) 0x33,(byte) 0x88,(byte) 0x07,(byte) 0xc7,(byte) 0x31,(byte)
            0xb1,(byte) 0x12,(byte) 0x10,(byte) 0x59,(byte) 0x27,(byte) 0x80,(byte) 0xec,(byte) 0x5f,(byte)
            0x60,(byte) 0x51,(byte) 0x7f,(byte) 0xa9,(byte) 0x19,(byte) 0xb5,(byte) 0x4a,(byte) 0x0d,(byte)
            0x2d,(byte) 0xe5,(byte) 0x7a,(byte) 0x9f,(byte) 0x93,(byte) 0xc9,(byte) 0x9c,(byte) 0xef,(byte)
            0xa0,(byte) 0xe0,(byte) 0x3b,(byte) 0x4d,(byte) 0xae,(byte) 0x2a,(byte) 0xf5,(byte) 0xb0,(byte)
            0xc8,(byte) 0xeb,(byte) 0xbb,(byte) 0x3c,(byte) 0x83,(byte) 0x53,(byte) 0x99,(byte) 0x61,(byte)
            0x17,(byte) 0x2b,(byte) 0x04,(byte) 0x7e,(byte) 0xba,(byte) 0x77,(byte) 0xd6,(byte) 0x26,(byte)
            0xe1,(byte) 0x69,(byte) 0x14,(byte) 0x63,(byte) 0x55,(byte) 0x21,(byte) 0x0c,(byte) 0x7d};
    public byte[] SBox = {
            (byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5,
            (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76,
            (byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0,
            (byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0,
            (byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC,
            (byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15,
            (byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A,
            (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75,
            (byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0,
            (byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84,
            (byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B,
            (byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF,
            (byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85,
            (byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8,
            (byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5,
            (byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2,
            (byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17,
            (byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73,
            (byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88,
            (byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB,
            (byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C,
            (byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79,
            (byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9,
            (byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08,
            (byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6,
            (byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A,
            (byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E,
            (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E,
            (byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94,
            (byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF,
            (byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68,
            (byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16};

    byte[][] matrixMix = { {(byte) 0x02, (byte) 0x03,(byte) 0x01,(byte) 0x01},
            {(byte) 0x01, (byte) 0x02,(byte) 0x03,(byte) 0x01},
            {(byte) 0x01, (byte) 0x01,(byte) 0x02,(byte) 0x03},
            {(byte) 0x03, (byte) 0x01,(byte) 0x01,(byte) 0x02} };

    byte[][] invMatrixMix = { {(byte) 0x0E, (byte) 0x0B,(byte) 0x0D,(byte) 0x09},
            {(byte) 0x09, (byte) 0x0E,(byte) 0x0B,(byte) 0x0D},
            {(byte) 0x0D, (byte) 0x09,(byte) 0x0E,(byte) 0x0B},
            {(byte) 0x0B, (byte) 0x0D,(byte) 0x09,(byte) 0x0E} };


	/* La clef courte K utilisée aujourd'hui est formée de 16 octets nuls */
	int longueur_de_la_clef = 16 ;
	byte K[] = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    } ;

    public byte W[] = new byte[240];

    public ArrayList<byte[]> roundKeys;

	/* Résultat du TP précédent : diversification de la clef courte K en une clef étendue W */

	static int Nr = 10;
	static int Nk = 4;
	int longueur_de_la_clef_etendue = 176;



    /* Le bloc à chiffrer aujourd'hui: 16 octets nuls */

	public byte State[] = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };

    public static byte[] Rcon = { (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1b, (byte) 0x36 } ;

    byte[] initVector;


    public Aes(byte[] initVector,byte[] keyAes) {
        this.initVector = initVector;
        K = keyAes;
    }

    public Aes() {
    }

    /* Programme principal */

	public static void main(String args[]) {
		Aes aes = new Aes() ;

        aes.initVector = aes.K;
        aes.encryptFile("src/G2/butokuden.jpg");
	}


    public void afficher_le_bloc(byte M[]) {
        for (int i=0; i<4; i++) { // Lignes 0 à 3
            System.out.print("          ");
            for (int j=0; j<4; j++) { // Colonnes 0 à 3
                System.out.print(String.format("%02X ", M[4*j+i]));
            }
            System.out.println();
        }
	}

	public void chiffrer(){
//        printRoundKeys();

        AddRoundKey(roundKeys.get(0));

        for (int i = 1; i < Nr; i++) {
            SubBytes();
            ShiftRows();
            MixColumns();
            AddRoundKey(roundKeys.get(i));
        }
        SubBytes();
        ShiftRows();
        AddRoundKey(roundKeys.get(Nr));
	}

	public void dechiffrer(){
        invAddRoundKey(roundKeys.get(Nr));
        invShiftRows();
        invSubBytes();

        for (int i = Nr-1; i > 0; i--) {
            invAddRoundKey(roundKeys.get(i));
            invMixColumns();
            invShiftRows();
            invSubBytes();
        }
        invAddRoundKey(roundKeys.get(0));
    }

    private void invMixColumns() {
	    byte[] subArray;
        for (int i = 0; i < State.length; i+=4) {
            subArray = getStateSubArray(i,i+4);
            updateStateArray(i,i+4,multiplyMatrixAndVector(invMatrixMix,subArray));
        }
    }


    private void invSubBytes() {
        for (int i = 0; i < State.length; i++) {
            int indexSub = Integer.parseInt(byteToString(State[i]),16);
            State[i] = invSBox[indexSub];
        }
    }


    private void invShiftRows() {
        byte[] row;
        byte[] unShiftedRow;
        for (int i = 0; i < State.length/4; i++) {
            row = getStateRow(i);
            unShiftedRow = invShiftRow(i, row);
            updateStateRow(i,unShiftedRow);
        }

    }

    private byte[] invShiftRow(int step, byte[] byteArray) {
        byte[] unShiftedRow = new byte[byteArray.length];
        int newPos;

        for (int i = 0; i < byteArray.length; i++) {
            newPos = i+step;
            unShiftedRow[newPos%byteArray.length] = byteArray[i];
        }
        return unShiftedRow;
    }

    private void invAddRoundKey(byte[] bytes) {
	    AddRoundKey(bytes);
    }


    /* Fonction mystérieuse qui calcule le produit de deux octets */
	byte gmul(byte a1, byte b1) {
		int a = Byte.toUnsignedInt(a1);
		int b = Byte.toUnsignedInt(b1);
		int p = 0;
		int hi_bit_set;
        for(int i = 0; i < 8; i++) {
            if((b & 1) == 1) p ^= a;
            hi_bit_set =  (a & 0x80);
            a <<= 1;
            if(hi_bit_set == 0x80) a ^= 0x1b;		
            b >>= 1;
        }
        return (byte) (p & 0xFF);
	}


	public void SubBytes(){
        subWord(State);
    }
	
	public void ShiftRows(){
        byte[] row;
        byte[] shiftedRow;
        for (int i = 0; i < State.length/4; i++) {
            row = getStateRow(i);
            shiftedRow = shiftRow(i, row);
            updateStateRow(i,shiftedRow);
        }
    }

    private void updateStateRow(int rowIndex, byte[] shiftedRow) {
        int index = 0;
        for (int i = rowIndex; i < State.length; i+=4) {
            State[i] = shiftedRow[index];
            index++;
        }
    }

    private byte[] getStateRow(int rowIndex) {
	    byte[] row = new byte[4];
	    int index = 0;
        for (int i = rowIndex; i < State.length; i+=4) {
            row[index] = State[i];
            index++;
        }
        return row;
    }


    public byte[] shiftRow(int step, byte[] byteArray){
        byte[] shiftedRow = new byte[byteArray.length];
        int newPos;

        for (int i = 0; i < byteArray.length; i++) {
            newPos = i-step;
            if(newPos < 0)
                shiftedRow[byteArray.length-Math.abs(newPos)%byteArray.length] = byteArray[i];
            else
                shiftedRow[i-step] = byteArray[i];
        }
        return shiftedRow;
    }


    public void MixColumns(){
        byte[] subArray;
        for (int i = 0; i < State.length; i+=4) {
            subArray = getStateSubArray(i,i+4);
            updateStateArray(i,i+4,multiplyMatrixAndVector(matrixMix,subArray));
        }
    }

    public byte[] multiplyMatrixAndVector(byte[][] firstMatrix, byte[] vector) {
        byte[] product = new byte[firstMatrix.length];

        for(int i = 0; i < firstMatrix[0].length; i++) {
            for (int j = 0; j < vector.length; j++) {
                product[i] = xor(product[i], gmul(firstMatrix[i][j],vector[j]));
            }
        }
        return product;
    }



    private byte[] getStateSubArray(int indexStart, int indexEnd) {
        byte[] subArray = new byte[indexEnd-indexStart];
        for (int i = 0; i < subArray.length; i++) {
            subArray[i] = State[indexStart+i];
        }
        return subArray;
    }
    private void updateStateArray(int indexStart, int indexEnd, byte[] arrayToUpdate){
        for (int i = 0; i < arrayToUpdate.length; i++) {
            State[indexStart+i] = arrayToUpdate[i];
        }
    }
	
	public void AddRoundKey(byte[] roundKey){
	    State = xorArray(roundKey,State);
    }

    private void printRoundKeys() {
        System.out.println("RoundKeys :");
        for(byte[] array : roundKeys){
            affiche_la_clef(array,16);
        }
    }


    private void splitByteArrayTo16Block(byte[] byteArray, ArrayList<byte[]> storageByteArrays) {
        for (int i = 0; i < byteArray.length; i+=16) {
            byte[] tempByteArray = new byte[16];
            for (int j = 0; j < tempByteArray.length; j++) {
                tempByteArray[j] = byteArray[i+j];
            }
            storageByteArrays.add(tempByteArray);
        }
    }

    public static void affiche_la_clef(byte clef[], int longueur) {
        for (int i=0; i<longueur; i++) { System.out.printf ("%02X ", clef[i]); }
        System.out.println();
    }
    public static String byteToString(byte byteValue){
        return String.format("%02X", byteValue);
    }


    public void calcule_la_clef_courte(String clef) {
        int len = clef.length();

        for (int i = 0; i < len; i += 2) {
            byte b = (byte) ((Character.digit(clef.charAt(i), 16) << 4)
                    + Character.digit(clef.charAt(i+1), 16));

            //System.out.printf("%02X ", b);
            K[i / 2] = b;

        }
    }

    private void subWord(byte[] byteArray) {
        for (int i = 0; i < byteArray.length; i++) {
            int indexSub = Integer.parseInt(byteToString(byteArray[i]),16);
            byteArray[i] = SBox[indexSub];
        }
    }

    public void rotWord(byte[] byteArray){
        byte tmp = byteArray[0];
        for (int i = 1; i < byteArray.length; i++) {
            byteArray[i-1] = byteArray[i];
        }
        byteArray[byteArray.length-1] = tmp;
    }

    public byte[] xorArray(byte[] byteArray, byte[] byteArrayXor){
        byte[] resultArray = new byte[byteArray.length];

        for (int i = 0; i < byteArray.length; i++)
            resultArray[i] = xor(byteArray[i], byteArrayXor[i]);

        return resultArray;
    }

    public byte xor(byte b1, byte b2) {
        return (byte) (Byte.toUnsignedInt(b1) ^ Byte.toUnsignedInt(b2));
    }


    public void calcule_la_clef_etendue() {
        if (longueur_de_la_clef == 16) {
            Nr = 10; Nk = 4;
        } else if (longueur_de_la_clef == 24) {
            Nr = 12; Nk = 6;
        } else {
            Nr = 14; Nk = 8;
        }

        for (int i = 0; i < longueur_de_la_clef; i++) {
            W[i] = K[i];
        }

        int colonnes_de_la_clef_etendue = 4 * (Nr + 1);

        byte[] tmp = new byte[4];

        for (int i = Nk; i < colonnes_de_la_clef_etendue; i++) {


            int indexTmp = 0;

            //recopie colonne W[i-1] dans tmp
            for(int j = (i*4)-4; j < i*4; j++){
                tmp[indexTmp++] = W[j];
            }

            if(i % Nk  == 0){
                rotWord(tmp);
                subWord(tmp);
                byte[] rconVector = {Rcon[(i/Nk)-1],(byte) 0x00, (byte) 0x00, (byte) 0x00};
                tmp = xorArray(tmp, rconVector);
            }
            else if (Nk > 6 && i % Nk == 4)
                subWord(tmp);

            byte[] arrayWIndexIMinusNk = new byte[4];

            for (int j = 0; j < arrayWIndexIMinusNk.length; j++) {
                arrayWIndexIMinusNk[j] = W[((i - Nk)*4) + j];
            }

            tmp = xorArray(arrayWIndexIMinusNk,tmp);


            for (int j = 0; j < tmp.length; j++) {
                W[(i*4) + j] = tmp[j];
            }

        }
    }

    public void calculClefs(){
        longueur_de_la_clef = 16;

//		calcule_la_clef_courte("2b7e151628aed2a6abf7158809cf4f3c");     // Fonction décodant la clef courte K

        calcule_la_clef_etendue();          // Fonction calculant la clef longue W

        longueur_de_la_clef_etendue = (Nr+1)*4*4;

        roundKeys = new ArrayList<>();


        splitByteArrayTo16Block(W,roundKeys);

    }

    public byte[] encryptFile(String imagePath){
        calculClefs();

        dataToEncrypt = readBytesFromFile(imagePath);
	    addPKCS5Padding();
        return encryptData();
    }

    private byte[] encryptData() {
	    dataSplittedBy16Block = new ArrayList<>();
        splitByteArrayTo16Block(dataToEncrypt,dataSplittedBy16Block);

        encryptedData = new byte[dataToEncrypt.length];

//        byte[] lastCryptedState = K;
        byte[] lastCryptedState = initVector;

        for (int i = 0; i < dataSplittedBy16Block.size(); i++) {
            //xor initVector et block16
            State = xorArray(dataSplittedBy16Block.get(i), lastCryptedState);

            chiffrer();

            lastCryptedState = State;
            storeState(i*16, encryptedData);
        }
        return encryptedData;
    }

    public byte[] decryptData(byte[] encryptedData) {
        calculClefs();
        decryptedData = new byte[encryptedData.length];

        dataSplittedBy16Block = new ArrayList<>();
        splitByteArrayTo16Block(encryptedData,dataSplittedBy16Block);

        byte[] lastCryptedState;

        for (int i = dataSplittedBy16Block.size()-1; i >= 0; i--) {
            State = dataSplittedBy16Block.get(i);

            dechiffrer();

            if(i == 0)
                lastCryptedState = initVector;
            else
                lastCryptedState = dataSplittedBy16Block.get(i-1);

            State = xorArray(State, lastCryptedState);
            storeState(i*16, decryptedData);
        }
        return removePKCS5Padding(decryptedData);
    }

    private void storeState(int positionStart, byte [] storageBytes) {
        for (int i = 0; i < 16; i++) {
            storageBytes[positionStart+i] = State[i];
        }
    }

    private byte[] removePKCS5Padding(byte[] byteArray) {
	    int paddingSize = byteArray[byteArray.length-1];
        return Arrays.copyOfRange(byteArray, 0, byteArray.length - paddingSize);
    }


    private void addPKCS5Padding() {
	    int byteSizeToAdd =  K.length - (dataToEncrypt.length % K.length);

	    if(byteSizeToAdd == 0)
	        byteSizeToAdd = K.length;

	    byte [] byteArrayToAdd = new byte[byteSizeToAdd];

        for (int i = 0; i < byteSizeToAdd; i++) {
            byteArrayToAdd[i] = (byte)byteSizeToAdd;
        }
        dataToEncrypt = concatArrays(dataToEncrypt, byteArrayToAdd);
    }

    private static byte[] concatArrays(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
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

}


import java.lang.String;

public class Diversification {

	// C'est la table de substitution
	public static byte[] SBox = { (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F,
			(byte) 0xC5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B, (byte) 0xFE, (byte) 0xD7, (byte) 0xAB,
			(byte) 0x76, (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47,
			(byte) 0xF0, (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF, (byte) 0x9C, (byte) 0xA4, (byte) 0x72,
			(byte) 0xC0, (byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F, (byte) 0xF7,
			(byte) 0xCC, (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1, (byte) 0x71, (byte) 0xD8, (byte) 0x31,
			(byte) 0x15, (byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96, (byte) 0x05,
			(byte) 0x9A, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2, (byte) 0xEB, (byte) 0x27, (byte) 0xB2,
			(byte) 0x75, (byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E, (byte) 0x5A,
			(byte) 0xA0, (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3, (byte) 0x29, (byte) 0xE3, (byte) 0x2F,
			(byte) 0x84, (byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC, (byte) 0xB1,
			(byte) 0x5B, (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39, (byte) 0x4A, (byte) 0x4C, (byte) 0x58,
			(byte) 0xCF, (byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D, (byte) 0x33,
			(byte) 0x85, (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F, (byte) 0x50, (byte) 0x3C, (byte) 0x9F,
			(byte) 0xA8, (byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38,
			(byte) 0xF5, (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21, (byte) 0x10, (byte) 0xFF, (byte) 0xF3,
			(byte) 0xD2, (byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44,
			(byte) 0x17, (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D, (byte) 0x64, (byte) 0x5D, (byte) 0x19,
			(byte) 0x73, (byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90,
			(byte) 0x88, (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14, (byte) 0xDE, (byte) 0x5E, (byte) 0x0B,
			(byte) 0xDB, (byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24,
			(byte) 0x5C, (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xE4,
			(byte) 0x79, (byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E,
			(byte) 0xA9, (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA, (byte) 0x65, (byte) 0x7A, (byte) 0xAE,
			(byte) 0x08, (byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4,
			(byte) 0xC6, (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F, (byte) 0x4B, (byte) 0xBD, (byte) 0x8B,
			(byte) 0x8A, (byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6,
			(byte) 0x0E, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9, (byte) 0x86, (byte) 0xC1, (byte) 0x1D,
			(byte) 0x9E, (byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E,
			(byte) 0x94, (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9, (byte) 0xCE, (byte) 0x55, (byte) 0x28,
			(byte) 0xDF, (byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42,
			(byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F, (byte) 0xB0, (byte) 0x54, (byte) 0xBB,
			(byte) 0x16 };


	public static byte[] Rcon = { (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1b, (byte) 0x36 } ;
    // Ce sont les constantes de ronde

    public static byte K[] = new byte[32];   // Une clef courte a une longueur maximale de 32 octets
	public static byte W[] = new byte[240];  // La longueur maximale de W est (14+1)*16=240 octets

	public static int longueur_de_la_clef;
	public static int longueur_de_la_clef_etendue;
	public static int Nr;
	public static int Nk;

    public static void affiche_la_clef(byte clef[], int longueur) {
        for (int i=0; i<longueur; i++) { System.out.printf ("%02X ", clef[i]); }
        System.out.println();
    }
    public static String byteToString(byte byteValue){
		return String.format("%02X", byteValue);
	}


	public static void calcule_la_clef_courte(String clef) {
		int len = clef.length();

		for (int i = 0; i < len; i += 2) {
			byte b = (byte) ((Character.digit(clef.charAt(i), 16) << 4)
					+ Character.digit(clef.charAt(i+1), 16));

			//System.out.printf("%02X ", b);
			K[i / 2] = b;

		}
    }

	private static void subWord(byte[] byteArray) {

//		affiche_la_clef(byteArray, 4);

		for (int i = 0; i < byteArray.length; i++) {
			int indexSub = Integer.parseInt(byteToString(byteArray[i]),16);
//			System.out.println(indexSub);
			byteArray[i] = SBox[indexSub];
		}
//		affiche_la_clef(byteArray, 4);
	}

	public static void rotWord(byte[] byteArray){
		byte tmp = byteArray[0];
		for (int i = 1; i < byteArray.length; i++) {
			byteArray[i-1] = byteArray[i];
		}
		byteArray[byteArray.length-1] = tmp;
	}

	public static byte[] xor(byte[] byteArray, byte[] byteArrayXor){
		byte[] resultArray = new byte[4];

		for (int i = 0; i < byteArray.length; i++)
			resultArray[i] = (byte) (byteArray[i] ^ byteArrayXor[i]);

		return resultArray;
	}

	public static void testRotWord(){
		byte[] testBytes = { (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B};
		affiche_la_clef(testBytes, 4);
		rotWord(testBytes);
		affiche_la_clef(testBytes, 4);
	}

    
	public static void calcule_la_clef_etendue() {
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

			//affiche colonne recopiée
//			for (int j = 0; j < 4; j++) {
//				System.out.println(tmp[j]);
//			}

			if(i % Nk  == 0){
				rotWord(tmp);
				subWord(tmp);
				byte[] rconVector = {Rcon[(i/Nk)-1],(byte) 0x00, (byte) 0x00, (byte) 0x00};
				tmp = xor(tmp, rconVector);
			}
			else if (Nk > 6 && i % Nk == 4)
				subWord(tmp);

			byte[] arrayWIndexIMinusNk = new byte[4];

			for (int j = 0; j < arrayWIndexIMinusNk.length; j++) {
				arrayWIndexIMinusNk[j] = W[((i - Nk)*4) + j];
			}
			
			tmp = xor(arrayWIndexIMinusNk,tmp);

			affiche_la_clef(tmp, 4);

			for (int j = 0; j < tmp.length; j++) {
				System.out.println(byteToString(tmp[j]));
				W[(i*4) + j] = tmp[j];
			}

		}
	}


	public static void calcul_clefs(){
		longueur_de_la_clef = 16;

		K = new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
		};

//		calcule_la_clef_courte("2b7e151628aed2a6abf7158809cf4f3c");     // Fonction décodant la clef courte K

		System.out.println("Clef courte :");
		affiche_la_clef(K, longueur_de_la_clef);

		calcule_la_clef_etendue();          // Fonction calculant la clef longue W

		System.out.println("Clef longue :");
		longueur_de_la_clef_etendue = (Nr+1)*4*4;

		affiche_la_clef(W, longueur_de_la_clef_etendue);

	}



	public static void main(String[] args) {
		/*if (args.length == 0) {
			System.out.println("Usage: java Diversification <clef en hexadécimal>");
			System.exit(1);
		}

		longueur_de_la_clef = args[0].length()/2;

		if ( (longueur_de_la_clef!=16) && (longueur_de_la_clef!=24) && (longueur_de_la_clef != 32) ) {
			System.out.println("Usage: java Diversification <clef en hexadécimal>");
			System.out.println("\t Une clef AES est formée de 32, 48, ou 64 chiffres,");
			System.out.println("\t c'est-à-dire 128, 192, ou 256 bits.");
			System.exit(1);
		}*/

		//System.out.println(43^126);
		calcul_clefs();
	}

}


/* 2nd test à effectuer:
   $ java Diversification 2b7e151628aed2a6abf7158809cf4f3c
   La clef est : 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C 
   Les clefs de rondes sont : 
   RoundKeys[00] =  2B  7E  15  16  28  AE  D2  A6  AB  F7  15  88  09  CF  4F  3C 
   RoundKeys[01] =  A0  FA  FE  17  88  54  2C  B1  23  A3  39  39  2A  6C  76  05 
   RoundKeys[02] =  F2  C2  95  F2  7A  96  B9  43  59  35  80  7A  73  59  F6  7F 
   RoundKeys[03] =  3D  80  47  7D  47  16  FE  3E  1E  23  7E  44  6D  7A  88  3B 
   RoundKeys[04] =  EF  44  A5  41  A8  52  5B  7F  B6  71  25  3B  DB  0B  AD  00 
   RoundKeys[05] =  D4  D1  C6  F8  7C  83  9D  87  CA  F2  B8  BC  11  F9  15  BC 
   RoundKeys[06] =  6D  88  A3  7A  11  0B  3E  FD  DB  F9  86  41  CA  00  93  FD 
   RoundKeys[07] =  4E  54  F7  0E  5F  5F  C9  F3  84  A6  4F  B2  4E  A6  DC  4F 
   RoundKeys[08] =  EA  D2  73  21  B5  8D  BA  D2  31  2B  F5  60  7F  8D  29  2F 
   RoundKeys[09] =  AC  77  66  F3  19  FA  DC  21  28  D1  29  41  57  5C  00  6E 
   RoundKeys[10] =  D0  14  F9  A8  C9  EE  25  89  E1  3F  0C  C8  B6  63  0C  A6 
   $
*/

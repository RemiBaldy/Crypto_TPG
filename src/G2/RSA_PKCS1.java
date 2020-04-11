package G2;

import java.math.BigInteger;
import java.util.Random;

public class RSA_PKCS1 {
    BigInteger publicE;
    BigInteger publicN;

    public RSA_PKCS1(BigInteger e, BigInteger n) {
        publicE = e;
        publicN = n;
    }

    public static void main(String[] args) throws Exception {


        BigInteger n = new BigInteger(
                "00af7958cb96d7af4c2e6448089362"+
                        "31cc56e011f340c730b582a7704e55"+
                        "9e3d797c2b697c4eec07ca5a903983"+
                        "4c0566064d11121f1586829ef6900d"+
                        "003ef414487ec492af7a12c34332e5"+
                        "20fa7a0d79bf4566266bcf77c2e007"+
                        "2a491dbafa7f93175aa9edbf3a7442"+
                        "f83a75d78da5422baa4921e2e0df1c"+
                        "50d6ab2ae44140af2b", 16);
        BigInteger e = BigInteger.valueOf(0x10001);
        BigInteger d = new BigInteger(
                "35c854adf9eadbc0d6cb47c4d11f9c"+
                        "b1cbc2dbdd99f2337cbeb2015b1124"+
                        "f224a5294d289babfe6b483cc253fa"+
                        "de00ba57aeaec6363bc7175fed20fe"+
                        "fd4ca4565e0f185ca684bb72c12746"+
                        "96079cded2e006d577cad2458a5015"+
                        "0c18a32f343051e8023b8cedd49598"+
                        "73abef69574dc9049a18821e606b0d"+
                        "0d611894eb434a59", 16);

        RSA_PKCS1 rsa_pkcs1 = new RSA_PKCS1(e,n);


        byte[] m = { 0x4B, 0x59, 0x4F, 0x54, 0x4F } ;
        System.out.println("Message clair      : " + toHex(m) );


        byte[] chiffré = rsa_pkcs1.encrypt(m);

        System.out.println("Message chiffré    : " + toHex(chiffré) );
    }

    public byte[] encrypt(byte[] msg){
        byte[] paddedMsg = addPaddingPKCS1(msg);
//        System.out.println(toHex(paddedMsg));
        BigInteger encrypted = chiffre(paddedMsg);
        return encrypted.toByteArray();
    }

    private BigInteger chiffre(byte[] paddedM) {
        BigInteger x = new BigInteger(1, paddedM);
        BigInteger c = x.modPow(publicE, publicN);
        return c;
    }

    private static byte[] addPaddingPKCS1(byte[] m) {
        int startPos = 128 - m.length;
        int paddingSize = 128 - m.length -3;

        byte[] paddedM = new byte[128];
        paddedM[0] = (byte) 0x00;
        paddedM[1] = (byte) 0x02;
        paddedM[paddingSize-1] = (byte) 0x00;

        byte[] randomBytes = new byte[paddingSize];
        new Random().nextBytes(randomBytes);

        for (int i = 0; i < randomBytes.length; i++) {
            paddedM[i+2] = randomBytes[i];
        }

        for (int i = 0; i < m.length; i++) {
            paddedM[startPos+i] = m[i];
        }
        return paddedM;
    }


    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) sb.append(String.format("0x%02X ", k));
        sb.append(" (" + données.length + " octets)");
        return sb.toString();
    }
}
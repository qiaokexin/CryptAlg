/******************************************************************************
 *  Compilation:  javac RSA.java
 *  Execution:    java RSA N
 *
 *  Generate an N-bit public and private RSA and CRTRSA key and use to encrypt
 *  and decrypt a random message.
 *
 *  % java RSA 50
 *  public  = 65537
 *  private = 553699199426609
 *  modulus = 825641896390631
 *  message   = 48194775244950
 *  encrpyted = 321340212160104
 *  decrypted = 48194775244950
 *
 *  Known bugs (not addressed for simplicity)
 *  -----------------------------------------
 *  - It could be the case that the message >= modulus. To avoid, use
 *    a do-while loop to generate key until modulus happen to be exactly N bits.
 *
 *  - It's possible that gcd(phi, publicKey) != 1 in which case
 *    the key generation fails. This will only happen if phi is a
 *    multiple of 65537. To avoid, use a do-while loop to generate
 *    keys until the gcd is 1. Done!
 *
 ******************************************************************************/

import java.math.BigInteger;
import java.security.SecureRandom;


public class RSA {
    private final static BigInteger one      = new BigInteger("1");
    private final static SecureRandom random = new SecureRandom();

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;
    private BigInteger p;
    private BigInteger q;
    private BigInteger dp;
    private BigInteger dq;
    private BigInteger qInv;
    private BigInteger phi;

    // generate an N-bit (roughly) public and private key
    RSA(int N) {
       /*
        do {
            p = BigInteger.probablePrime(N / 2, random);
            q = BigInteger.probablePrime(N / 2, random);
            phi = (p.subtract(one)).multiply(q.subtract(one));
            modulus = p.multiply(q);
            publicKey = new BigInteger("65537");     // common value in practice = 2^16 + 1
        } while (publicKey.gcd(phi).subtract(one).signum() != 0);

        privateKey = publicKey.modInverse(phi);
        dp = privateKey.mod(p.subtract(one));
        dq = privateKey.mod(q.subtract(one));
        qInv = q.modInverse(p);
*/
        p = new BigInteger("CA464401C0CBBF701B1B36C03740D4E2AEA0576E698437AA66A9EC59F38FFB1D",16);
        q = new BigInteger("A65DEB1467A03A3BBBFB220D350B0D8EFFA1B603CC33CB15902FE3824F38F6AF",16);
        dp =new BigInteger("86d982abd5dd2a4abcbccf2acf808dec746ae4f44658251c4471483bf7b55213",16);
        dq = new BigInteger("6EE94762EFC026D27D5216B378B20909FFC1240288228763B5754256DF7B4F1F",16);
        qInv = new BigInteger("1DD73A2F2B9B4625E5020301834F4B0DD5145BA779EC4913DD7D2FE6546B089F",16);
        modulus = p.multiply(q);
        //modulus = new BigInteger();

        phi = (p.subtract(one)).multiply(q.subtract(one));
        publicKey = new BigInteger("3");     // common value in practice = 2^16 + 1
        privateKey = publicKey.modInverse(phi);
        //privateKey = dp.multiply(q.subtract(one).modInverse(p.subtract(one))).add(dq.multiply(p.subtract(one).modInverse(q.subtract(one))));
        //publicKey = privateKey.modInverse(phi);
    }


    BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, modulus);
    }

    BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(privateKey, modulus);
    }

    BigInteger CRT(BigInteger message){
        BigInteger m1 = message.modPow(dp, p);
        BigInteger m2 = message.modPow(dq, q);
        BigInteger h ;
        if (m1.subtract(m2).signum() > 0){
            h = qInv.multiply(m1.subtract(m2)).mod(p);
        }else
        {
            h = qInv.multiply(m1.add(p.multiply(q.divide(p).add(one))).subtract(m2)).mod(p);
        }
        return m2.add(h.multiply(q)).mod(modulus);
    }

    public String toString() {
        String s = "";
        s += "public  = " + publicKey.toString(16).toUpperCase()  + "\n";
        s += "private = " + privateKey.toString(16).toUpperCase() + "\n";
        s += "modulus = " + modulus.toString(16).toUpperCase() + "\n";
        s += "p = " + p.toString(16).toUpperCase() + "\n";
        s += "q = " + q.toString(16).toUpperCase() + "\n";
        s += "dp = " + dp.toString(16).toUpperCase() + "\n";
        s += "dp = " + privateKey.mod(p.subtract(one)).toString(16).toUpperCase() + "\n";
        s += "dq = " + dq.toString(16).toUpperCase() + "\n";
        s += "qInv = " + qInv.toString(16).toUpperCase() + "\n";
        s += "qInv = " + q.modInverse(p).toString(16).toUpperCase();

        return s;
    }


    public static void main(String[] args) {
        //int N = Integer.parseInt(args[0]);
        int N = 512;
        RSA key = new RSA(N);
        System.out.println(key);

        // create random message, encrypt and decrypt
        BigInteger message = new BigInteger(N-1, random);
            message = new BigInteger("8D7121B8C890332A8A",16);

        //// create message by converting string to integer
        // String s = "test";
        // byte[] bytes = s.getBytes();
        // BigInteger message = new BigInteger(bytes);

        BigInteger encrypt = key.encrypt(message);
        BigInteger decrypt = key.decrypt(message);
        BigInteger CRT = key.CRT(message);
        BigInteger encryptb = key.encrypt(CRT);
        System.out.println("message   = " + message.toString(16).toUpperCase());
        System.out.println("encrypted = " + encrypt.toString(16).toUpperCase());
        System.out.println("CRT       = " + CRT.toString(16).toUpperCase());
        System.out.println("decrypted = " + decrypt.toString(16).toUpperCase());
        System.out.println("encryptb = " + encryptb.toString(16).toUpperCase());



    }
}



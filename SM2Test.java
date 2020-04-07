package SM2;
/* Compiling by JKD7, major version 51
 * @author Qiao Kexin
 * @Email: qiaokexin@bctest.com
 */

/* Nonsupersingular EC over the finite binary field GF(2^m)
 * y^2 + xy = x^3 + ax^2 + b  a,b \in GF(2^m)
 *
 */

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;


public class SM2Test {

    public static BigInteger Sign_r;
    public static BigInteger Sign_s;
    public static String Sign_r_str;
    public static String Sign_s_str;

    private final static SecureRandom random = new SecureRandom();
    private final static BigInteger one = new BigInteger("1");

    public static boolean debug = true;
    public static BigInteger a;
    public static BigInteger b;
    public static BigInteger p;
    public static BigInteger n;
    public static BigInteger G_x;
    public static BigInteger G_y;
    public static ECPoint basePoint;

    public static ECCurve myCurve;


    public SM2Test(String ast, String bst, String G_xst, String G_yst, String pst, String nst){

        /*
        G_x = new BigInteger("36AF93BFF765C2150A948827D97CF68F5F83E0D0C7411AE313A89ABF50224BBAE8C2F76271040290884CF5629DAB279D49AB0F98",16);
        G_y = new BigInteger("1952C13B138703B04EA0D313944A8B1E9AE7882380AD83907F12F2A937C2503ADA9E6BF01CA1F76FDF9032C79F130EB2BEA4C102",16);
        p = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF",16);
        a = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBD324",16);
        b = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCC3EC75",16);
        n = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB3CC92414CF706022B36F1C0338AD63CF181B0E71A5E106AF79",16);
        */
        /*
        //from SM2 official doc
        G_x = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",16);
        G_y = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",16);
        p = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",16);
        a = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",16);
        b = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",16);
        n = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",16);
        */
        /*
        //from NXP
        a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",16);
        b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",16);
        G_x = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",16);
        G_y = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",16);
        p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",16);
        n = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16);
        basePoint = new ECPoint(G_x, G_y);
    */


        a = new BigInteger(ast,16);
        b = new BigInteger(bst,16);
        G_x = new BigInteger(G_xst,16);
        G_y = new BigInteger(G_yst,16);
        p = new BigInteger(pst,16);
        n = new BigInteger(nst,16);

        a= a.mod(p);
        b=b.mod(p);

        myCurve = new ECCurve.Fp(p,a,b,n,BigInteger.ONE);
        basePoint =myCurve.createPoint(G_x,G_y);
        /*
        //from Infineon
        a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",16);
        b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",16);
        G_x = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",16);
        G_y = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",16);
        p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",16);
        n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",16);
        basePoint = new ECPoint(G_x, G_y);
    */
    }


    public static void SM2Sign(String digest_str, String dA_str){
        BigInteger digest = new BigInteger(digest_str,16);
        BigInteger dA = new BigInteger(dA_str,16);
        outer:
        for (;true;) {

            BigInteger k = new BigInteger(256, random);
            //BigInteger k =new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",16);
            ECPoint Q = basePoint.multiply(k).normalize();
            if (debug) {
                System.out.println("kG x = " + Q.getAffineXCoord().toBigInteger().toString(16).toUpperCase());
                System.out.println("kG y = " + Q.getAffineYCoord().toBigInteger().toString(16).toUpperCase());
            }
            BigInteger r = digest.add(Q.getAffineXCoord().toBigInteger()).mod(n);
            if (r.signum() == 0 | r.add(k).equals(n)) {

                continue outer;
            }

            BigInteger Inv;
            Inv = dA.add(one).modInverse(n);
            if (debug) {
                System.out.println("Inv = " + Inv.toString(16).toUpperCase());
            }
            BigInteger s = Inv.multiply(k.subtract(r.multiply(dA))).mod(n);
            if (s.signum()==0) continue outer;
            else {
                if(debug) {
                    System.out.println("r = " + r.toString(16).toUpperCase());
                    System.out.println("s = " + s.toString(16).toUpperCase());
                }
                Sign_r = r;
                Sign_s = s;
                Sign_r_str = r.toString(16).toUpperCase();
                Sign_s_str = s.toString(16).toUpperCase();
                return;
            }
        }

    }
    public static void SM2Sign_fixed(String digest_str, String dA_str, String k_str){
        //with fixed random number k

        BigInteger digest = new BigInteger(digest_str,16);
        BigInteger dA = new BigInteger(dA_str,16);
        BigInteger k = new BigInteger(k_str,16);
        outer:
        for (;true;) {

            //BigInteger k = new BigInteger(256, random);
            //BigInteger k =new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",16);
            ECPoint Q = basePoint.multiply(k).normalize();
            if (debug) {
                System.out.println("kG x = " + Q.getAffineXCoord().toBigInteger().toString(16).toUpperCase());
                System.out.println("kG y = " + Q.getAffineYCoord().toBigInteger().toString(16).toUpperCase());
            }
            BigInteger r = digest.add(Q.getAffineXCoord().toBigInteger()).mod(n);
            if (r.signum() == 0 | r.add(k).equals(n)) {

                continue outer;
            }

            BigInteger Inv;
            Inv = dA.add(one).modInverse(n);
            if (debug) {
                System.out.println("Inv = " + Inv.toString(16).toUpperCase());
            }
            BigInteger s = Inv.multiply(k.subtract(r.multiply(dA))).mod(n);
            if (s.signum()==0) continue outer;
            else {
                if(debug) {
                    System.out.println("r = " + r.toString(16).toUpperCase());
                    System.out.println("s = " + s.toString(16).toUpperCase());
                }
                Sign_r = r;
                Sign_s = s;
                Sign_r_str = r.toString(16).toUpperCase();
                Sign_s_str = s.toString(16).toUpperCase();
                return;
            }
        }

    }

    public static boolean SM2Verify(BigInteger digest, BigInteger r, BigInteger s, ECPoint PA){
        if (r.mod(n).signum()==0){
            System.out.println("Fail: r not in [1,n-1]");
            return false;
        }
        if (s.mod(n).signum()==0){
            System.out.println("Fail: s not in [1,n-1]");
            return false;
        }
        BigInteger t = r.add(s).mod(n);

        if (t.signum()==0){
            System.out.println("Fail: t==0");
            return false;
        }
        if (debug) {
            System.out.println("t = " + t.toString(16).toUpperCase());
        }

        ECPoint VP = basePoint.multiply(s).add(PA.multiply(t)).normalize();
        if (debug) {
            System.out.println("x1' = " + VP.getAffineXCoord().toBigInteger().toString(16).toUpperCase());
            System.out.println("y1' = " + VP.getAffineYCoord().toBigInteger().toString(16).toUpperCase());
        }
        BigInteger R1 = digest.add(VP.getAffineXCoord().toBigInteger()).mod(n);
        if (debug) {
            System.out.println("R = " + R1.toString(16).toUpperCase());
        }
        if (R1.equals(r)) {
            if (debug) System.out.println("Verify success!");
            return true;
        }
        else{
            System.out.println("Fail");
            return false;
        }
    }

    public static boolean BCTC_SM2Verify(byte[] r, byte[] s){
        if (r.length != 32) System.out.println(" r is not 32 bytes");
        if (s.length != 32) System.out.println(" s is not 32 bytes");
        String string_r="";
        String string_s="";
        for (int i=0; i<32;i++){
            String hex_r = Integer.toHexString(r[i]&0xff);
            if (hex_r.length()==1) {hex_r ='0'+hex_r;}
            string_r = string_r+hex_r;

            String hex_s = Integer.toHexString(s[i]&0xff);
            if (hex_s.length()==1) {hex_s ='0'+hex_s;}
            string_s = string_s+hex_s;
        }

        //System.out.println(string_r);
        //System.out.println(string_s);
        BigInteger BI_r = new BigInteger(string_r,16);
        BigInteger BI_s = new BigInteger(string_s,16);

        //from Infineon
        /*
        a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",16);
        b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",16);
        G_x = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",16);
        G_y = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",16);
        p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",16);
        n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",16);
        basePoint = new ECPoint(G_x, G_y);
        */
        BigInteger dA = new BigInteger("8D6BE3ED414D478C50EF69E1F243B0603F1D1F3FE540DE535CEECA6E4592F759",16);
        BigInteger digest = new BigInteger("AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD", 16);

        ECPoint PA = basePoint.multiply(dA).normalize();

        return SM2Verify(digest, BI_r, BI_s, PA);
    }
    //public static boolean BCTC_SM2Verify_par(String ast, String bst, String G_xst, String G_yst, String pst, String nst, String dAst, String digestst, String r, String s){
    public static boolean BCTC_SM2Verify_par(String dAst, String digestst, String r, String s){


        //System.out.println(string_r);
        //System.out.println(string_s);
        BigInteger BI_r = new BigInteger(r,16);
        BigInteger BI_s = new BigInteger(s,16);


        BigInteger dA = new BigInteger(dAst,16);
        BigInteger digest = new BigInteger(digestst, 16);

        ECPoint PA =basePoint.multiply(dA).normalize();

        return SM2Verify(digest, BI_r, BI_s, PA);
    }

    public static void main(String[] args){

        String a, b, G_x, G_y, p, n, ENTL, ID,A_x, A_y;

        //SM2 officical doc
        /*
        G_x = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
        G_y = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
        p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
        a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
        b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
        n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";

         */
        //from NXP
        /*
        a="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
        b = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
        G_x = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        G_y = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
        p = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        n = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
        */
        a=  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
        b=  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
        G_x="32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
        G_y="BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
        p=  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
        n=  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
        A_x="160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C94232";
        A_y="4A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F";
        ENTL ="0080";
        ID ="000102030405060708090A0B0C0D0E0F";
       /* a.replaceAll(" ", "");
        b.replaceAll(" ", "");
        G_x.replaceAll(" ", "");
        G_y.replaceAll(" ", "");
        p.replaceAll(" ", "");
        n.replaceAll(" ", "");
        */
        SM2Test T= new SM2Test(a,b,G_x,G_y,p,n);
        //String dA="128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
        //String digest ="AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";
        //String digest2 ="AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDF";
        //BigInteger dA = new BigInteger("8D6BE3ED414D478C50EF69E1F243B0603F1D1F3FE540DE535CEECA6E4592F759",16);
        //BigInteger digest = new BigInteger("AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD", 16);
        //ECPoint pk = multiply(a.basePoint,dA);
        //System.out.println("pk x = " + pk.getAffineX().toString(16).toUpperCase());
        //System.out.println("pk y = " + pk.getAffineY().toString(16).toUpperCase());
        //String r = "232EAA6E6F4F1A00EED384640C012684F11783401A19E59861EA7F9BDB8E8BC5";
        //String s = "1570CA5D1FE6697FC138E224B1CB82DCFED81337BCC5BBBFB8A0363E123B8975";
        try {
            /*
            String pre_ZA = "0090 414C494345313233405941484F4F2E434F4D" +
                    "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498" +
                    "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A" +
                    "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D" +
                    "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" +
                    "0AE4C779 8AA0F119 471BEE11 825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A" +
                    "7C0240F8 8F1CD4E1 6352A73C 17B7F16F 07353E53 A176D684 A9FE0C6B B798E857";
            */
            String pre_ZA = ENTL + ID +a + b+ G_x +G_y+A_x+A_y;
            String ZA = SM3.hash(pre_ZA);
            String m = "00112233445566778899AABBCCDDEEFF";

            String digest = SM3.hash(ZA+m);
            System.out.println("digest "+ digest);
            /*
            String k = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
            System.out.println("Test");
            SM2Sign(digest, dA);
            System.out.println("r = " + T.Sign_r_str);
            System.out.println("s = " + T.Sign_s_str);

            System.out.println(BCTC_SM2Verify_par(dA,digest,T.Sign_r_str,T.Sign_s_str));
            SM2Sign_fixed(digest,dA,k);
            System.out.println("r = " + T.Sign_r_str);
            System.out.println("s = " + T.Sign_s_str);
            System.out.println(BCTC_SM2Verify_par(dA,digest,T.Sign_r_str,T.Sign_s_str));

            */
            String r = "c873135547f65987b622b951de41e55ed4296386b811765b9bea8fd9fd7e0bfe";
            String s = "df9286b7df50196211dacd41d78cd80c21fe5f97a2c39a175b544278c8a5b180";
            BigInteger BIA_x,BIA_y,BIdigest,BIr,BIs;
            BIA_x=new BigInteger(A_x,16);
            BIA_y = new BigInteger(A_y,16);
            BIdigest = new BigInteger(digest,16);
            BIr= new BigInteger(r,16);
            BIs = new BigInteger(s,16);
            ECPoint PA =myCurve.createPoint(BIA_x,BIA_y);

            SM2Verify(BIdigest, BIr, BIs, PA);

        } catch (IOException e) {
            System.out.println("IOException");
        }



    }
}

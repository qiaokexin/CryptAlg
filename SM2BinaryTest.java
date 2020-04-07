package SM2;
/* Compiling by JKD7, major version 51
 * @author Qiao Kexin
 * @Email: qiaokexin@bctest.com
 */

/* Nonsupersingular EC over the finite binary field GF(2^m)
 * trinomial and pentanomial primarily used
 * y^2 + xy = x^3 + ax^2 + b  a,b \in GF(2^m)
 *
 */

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;


public class SM2BinaryTest {

    public static BigInteger Sign_r;
    public static BigInteger Sign_s;
    public static String Sign_r_str;
    public static String Sign_s_str;

    private final static SecureRandom random = new SecureRandom();


    public static boolean debug = false;
    public static BigInteger a;
    public static BigInteger b;

    public static int m; //degree of irreducible polynomial
    public static int[] k; // orders of middle terms in irreducible polynomial
    public static BigInteger n;
    public static BigInteger G_x;
    public static BigInteger G_y;
    public static ECPoint basePoint;
    public static ECCurve myCurve;


    public SM2BinaryTest(String ast, String bst, String G_xst, String G_yst, int m, int[] k, String nst){




        a = new BigInteger(ast,16);
        b = new BigInteger(bst,16);

        G_x = new BigInteger(G_xst,16);
        G_y = new BigInteger(G_yst,16);
        n = new BigInteger(nst,16);
        //p = new BigInteger(pst,16);
        if (k.length == 1) {
            myCurve = new ECCurve.F2m(m, k[0], a, b,n,BigInteger.ONE);
        }
        else if (k.length ==3){
            myCurve = new ECCurve.F2m(m, k[0],k[1],k[2], a, b,n,BigInteger.ONE);


        }else{
            System.out.println("Only trinomial and pentanomial are supported!");
        }




        basePoint =myCurve.createPoint(G_x,G_y);

        //curve2 = new ECCurve.Fp(p, a,b,n,BigInteger.ONE);
        //basePoint = curve2.createPoint(G_x, G_y);

    }
    public static void PrintG (){
        System.out.println("Gx="+ basePoint.getAffineXCoord().toBigInteger().toString(16).toUpperCase());
        System.out.println(basePoint.getAffineYCoord().toBigInteger().toString(16).toUpperCase());
        return;
    }

    public static void SM2Sign(String digest_str, String dA_str){
        BigInteger digest = new BigInteger(digest_str,16);
        BigInteger dA = new BigInteger(dA_str,16);
        outer:
        for (;true;) {

            BigInteger k = new BigInteger(256, random);
            //BigInteger k =new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",16);
            ECPoint Q = basePoint.multiply(k).normalize();//Need to be normalized

            if (debug) {
                System.out.println("kG x = " + Q.getAffineXCoord().toBigInteger().toString(16).toUpperCase());
                System.out.println("kG y = " + Q.getAffineYCoord().toBigInteger().toString(16).toUpperCase());
            }
            BigInteger r = digest.add(Q.getAffineXCoord().toBigInteger()).mod(n);
            if (r.signum() == 0 | r.add(k).equals(n)) {

                continue outer;
            }

            BigInteger Inv;
            Inv = dA.add(BigInteger.ONE).modInverse(n);
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
            Inv = dA.add(BigInteger.ONE).modInverse(n);
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


    //public static boolean BCTC_SM2Verify_par(String ast, String bst, String G_xst, String G_yst, String pst, String nst, String dAst, String digestst, String r, String s){
    public static boolean BCTC_SM2Verify_par(String dAst, String digestst, String r, String s){


        //System.out.println(string_r);
        //System.out.println(string_s);
        BigInteger BI_r = new BigInteger(r,16);
        BigInteger BI_s = new BigInteger(s,16);


        BigInteger dA = new BigInteger(dAst,16);
        BigInteger digest = new BigInteger(digestst, 16);
        ECPoint PA = basePoint.multiply(dA);

        return SM2Verify(digest, BI_r, BI_s, PA);
    }
/*
    public static void main(String[] args){


        //SM2 officical doc
        String G_x = "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD";
        String G_y = "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E";
        String a = "0";
        String b = "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B";
        String n = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D";

        int[] k = new int[1];
        k[0]=12;

        SM2BinaryTest T= new SM2BinaryTest(a,b,G_x,G_y,257,k, n);
        String dA="771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931";

        try {
            //System.out.println(SM3.hash(SM3.byteArrayToHexString("abc".getBytes())));
            //String pre_ZA = "";

            //String ZA = SM3.hash(pre_ZA);
            String ZA = "26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5";
            String m = "6D65737361676520646967657374";

            String digest = SM3.hash(ZA+m);
            System.out.println("digest "+ digest);
            String rn = "36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6";
            System.out.println("Test");
            SM2Sign(digest, dA);
            System.out.println("SM2Sign");
            System.out.println("r = " + T.Sign_r_str);
            System.out.println("s = " + T.Sign_s_str);

            System.out.println(BCTC_SM2Verify_par(dA,digest,T.Sign_r_str,T.Sign_s_str));
            SM2Sign_fixed(digest,dA,rn);
            System.out.println("SM2Sign_fixed");
            System.out.println("r = " + T.Sign_r_str);
            System.out.println("s = " + T.Sign_s_str);
            System.out.println(BCTC_SM2Verify_par(dA,digest,T.Sign_r_str,T.Sign_s_str));

            PrintG();


        } catch (IOException e) {
            System.out.println("IOException");
        }



    }*/
}
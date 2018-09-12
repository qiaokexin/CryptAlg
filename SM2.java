import java.security.spec.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ECC {

    public static BigInteger Sign_r;
    public static BigInteger Sign_s;

    private final static SecureRandom random = new SecureRandom();
    private final static BigInteger one = new BigInteger("1");

    public static boolean debug = false;
    private static BigInteger a;
    private static BigInteger b;
    private static BigInteger p;
    private static BigInteger n;
    private static BigInteger G_x;
    private static BigInteger G_y;
    private static ECPoint basePoint;

    ECC(){

        G_x = new BigInteger("36AF93BFF765C2150A948827D97CF68F5F83E0D0C7411AE313A89ABF50224BBAE8C2F76271040290884CF5629DAB279D49AB0F98",16);
        G_y = new BigInteger("1952C13B138703B04EA0D313944A8B1E9AE7882380AD83907F12F2A937C2503ADA9E6BF01CA1F76FDF9032C79F130EB2BEA4C102",16);
        p = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF",16);
        a = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBD324",16);
        b = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCC3EC75",16);
        n = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB3CC92414CF706022B36F1C0338AD63CF181B0E71A5E106AF79",16);

        /*
        //from SM2 official doc
        G_x = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",16);
        G_y = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",16);
        p = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",16);
        a = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",16);
        b = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",16);
        n = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",16);
        */

        basePoint = new ECPoint(G_x, G_y);

    }
    public static ECParameterSpec MyCurve(){

        EllipticCurve myCurve = new EllipticCurve(new ECFieldFp(p),a,b);

        final ECParameterSpec myECParameter = new ECParameterSpec(myCurve, basePoint, n, 1);
        return myECParameter;

    }

    public static ECPoint negate(ECPoint P){
        if(P.equals(ECPoint.POINT_INFINITY)) return P;

        return new ECPoint(P.getAffineX(),P.getAffineY().negate().mod(p));
    }
    
    public static ECPoint add(ECPoint P, ECPoint Q){
        if (P.equals(ECPoint.POINT_INFINITY)) return Q;
        if (Q.equals(ECPoint.POINT_INFINITY)) return P;
        if (P.equals(negate(Q))) return ECPoint.POINT_INFINITY;
        if(P.equals(Q)){
            return twice(P);
        }

        BigInteger lambda = Q.getAffineY().subtract(P.getAffineY()).multiply((Q.getAffineX().subtract(P.getAffineX())).modInverse(p)).mod(p);

        BigInteger xR = lambda.pow(2).subtract(P.getAffineX()).subtract(Q.getAffineX());
        BigInteger yR = lambda.multiply(P.getAffineX().subtract(xR)).subtract(P.getAffineY());

        xR = xR.mod(p);
        yR = yR.mod(p);

        ECPoint R = new ECPoint(xR,yR);

        return R;
    }

    public static ECPoint twice(ECPoint P){
        if(P.equals(ECPoint.POINT_INFINITY)) return P;


        BigInteger lambda = BigInteger.valueOf(3).multiply(P.getAffineX().pow(2)).add(ECC.MyCurve().getCurve().getA()).multiply((BigInteger.valueOf(2).multiply(P.getAffineY())).modInverse(p));

        BigInteger xR = lambda.pow(2).subtract(P.getAffineX()).subtract(P.getAffineX());
        BigInteger yR = lambda.multiply(P.getAffineX().subtract(xR)).subtract(P.getAffineY());

        xR = xR.mod(p);
        yR = yR.mod(p);


        ECPoint R = new ECPoint(xR,yR);

        return R;
    }

    public static ECPoint multiply(ECPoint P, BigInteger k){

        if(P.equals(ECPoint.POINT_INFINITY)){
            return P;
        }

        if(k.signum()==0){
            return ECPoint.POINT_INFINITY;
        }

        ECPoint Itr = ECPoint.POINT_INFINITY;

        for (int i = k.bitLength(); i >0; i--){

            Itr = twice(Itr);
            if (k.testBit(i-1)) Itr = add(Itr, P);
            if (debug) {
                System.out.println(i);
                System.out.println(Itr.getAffineX().toString(16).toUpperCase());
                System.out.println(Itr.getAffineY().toString(16).toUpperCase());
            }
        }
    if (debug) {
        BigInteger h = k.multiply(BigInteger.valueOf(3));
        ECPoint neg = negate(P);
        ECPoint R = P;

        for (int i = h.bitLength() - 2; i > 0; i--) {
            System.out.println(i);
            R = twice(R);

            boolean hBit = h.testBit(i);
            boolean eBit = k.testBit(i);

            if (hBit != eBit) {
                R = add(R, (hBit ? P : neg));
            }
        }

        if (Itr.equals(R)) System.out.println("right");
        else System.out.println("wrong");
    }
        return Itr;
    }

    public static void SM2Sign(BigInteger digest, BigInteger dA){



        outer:
        for (;true;) {

            BigInteger k = new BigInteger(256, random);
            //BigInteger k =new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",16);
            ECPoint Q = multiply(basePoint, k);
            if (debug) {
                System.out.println("kG x = " + Q.getAffineX().toString(16).toUpperCase());
                System.out.println("kG y = " + Q.getAffineY().toString(16).toUpperCase());
            }
            BigInteger r = digest.add(Q.getAffineX()).mod(n);
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
        ECPoint VP = add(multiply(basePoint,s),multiply(PA,t));
        if (debug) {
            System.out.println("x1' = " + VP.getAffineX().toString(16).toUpperCase());
            System.out.println("y1' = " + VP.getAffineY().toString(16).toUpperCase());
        }
        BigInteger R1 = digest.add(VP.getAffineX()).mod(n);
        if (debug) {
            System.out.println("R = " + R1.toString(16).toUpperCase());
        }
        if (R1.equals(r)) {
            System.out.println("Verify success!");
            return true;
        }
        else{
            System.out.println("Fail");
            return false;
        }
    }

    public static void main(String[] args){

        ECC sm2 = new ECC();

        BigInteger dA = new BigInteger(256,random);
        ECPoint PA = sm2.multiply(sm2.basePoint, dA);
        BigInteger digest = new BigInteger(256,random);
  /*
        BigInteger dA = new BigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",16);
        BigInteger digest = new BigInteger("B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76", 16);
        ECPoint PA = sm2.multiply(sm2.basePoint, dA);
*/
        //System.out.println("dA = " + dA.toString(16).toUpperCase());
        //System.out.println("PA x = " + PA.getAffineX().toString(16).toUpperCase());
        //System.out.println("PA y = " + PA.getAffineY().toString(16).toUpperCase());
        SM2Sign(digest, dA);
        System.out.println("Sign_r = " + Sign_r.toString(16).toUpperCase());
        System.out.println("Sign_s = " + Sign_s.toString(16).toUpperCase());
        SM2Verify(digest, Sign_r, Sign_s, PA);
        if (debug) {
            System.out.println(sm2.basePoint.getAffineX().toString(16).toUpperCase());
            System.out.println(sm2.basePoint.getAffineY().toString(16).toUpperCase());
            System.out.println(PA.getAffineX().toString(16).toUpperCase());
            System.out.println(PA.getAffineY().toString(16).toUpperCase());
        }


    }
}

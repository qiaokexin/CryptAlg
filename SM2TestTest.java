
package SM2;

import junit.framework.TestCase;

import java.io.IOException;

//import static SM2.SM2Test.*;


public class SM2TestTest extends TestCase {

    public void testBCTC_SM2Verify_par() {
        String G_x, G_y, p, a, b, n, dA, m, digest, pre_ZA, ZA;
        G_x = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
        G_y = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
        p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
        a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
        b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
        n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";

        SM2Test T = new SM2Test(a,b,G_x,G_y,p,n);
        dA="128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";

        try {
            //System.out.println(SM3.hash(SM3.byteArrayToHexString("abc".getBytes())));
            pre_ZA = "0090 414C494345313233405941484F4F2E434F4D" +
                    "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498" +
                    "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A" +
                    "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D" +
                    "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" +
                    "0AE4C779 8AA0F119 471BEE11 825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A" +
                    "7C0240F8 8F1CD4E1 6352A73C 17B7F16F 07353E53 A176D684 A9FE0C6B B798E857";

            ZA = SM3.hash(pre_ZA);
            m = "6D657373 61676520 64696765 7374";

            digest = SM3.hash(ZA+m);
            System.out.println("digest "+ digest);
            String rn = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
            System.out.println("Test");
            SM2Test.SM2Sign(digest, dA);
            System.out.println("r = " + T.Sign_r_str);
            System.out.println("s = " + T.Sign_s_str);

            System.out.println(SM2Test.BCTC_SM2Verify_par(dA,digest,T.Sign_r_str,T.Sign_s_str));
            SM2Test.SM2Sign_fixed(digest,dA,rn);
            System.out.println("r = " + T.Sign_r_str);
            System.out.println("s = " + T.Sign_s_str);
            System.out.println(SM2Test.BCTC_SM2Verify_par(dA,digest,T.Sign_r_str,T.Sign_s_str));


            System.out.println("SM2BinaryTest:");
            //SM2 officical doc
            G_x = "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD";
            G_y = "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E";
            a = "0";
            b = "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B";
            n = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D";



            int[] k = new int[1];
            k[0]=12;

            SM2BinaryTest T2= new SM2BinaryTest(a,b,G_x,G_y,257,k, n);
            dA="771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931";


            //System.out.println(SM3.hash(SM3.byteArrayToHexString("abc".getBytes())));
            //pre_ZA = "";

            //String ZA = SM3.hash(pre_ZA);
            ZA = "26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5";
            m = "6D65737361676520646967657374";

            digest = SM3.hash(ZA+m);
            System.out.println("digest "+ digest);
            rn = "36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6";
            System.out.println("Test");
            T2.SM2Sign(digest, dA);
            System.out.println("SM2Sign");
            System.out.println("r = " + T2.Sign_r_str);
            System.out.println("s = " + T2.Sign_s_str);

            System.out.println(T2.BCTC_SM2Verify_par(dA,digest,T2.Sign_r_str,T2.Sign_s_str));
            T2.SM2Sign_fixed(digest,dA,rn);
            System.out.println("SM2Sign_fixed");
            System.out.println("r = " + T2.Sign_r_str);
            System.out.println("s = " + T2.Sign_s_str);
            System.out.println(T2.BCTC_SM2Verify_par(dA,digest,T2.Sign_r_str,T2.Sign_s_str));




        }catch (IOException e) {
            System.out.println("IOException");
        }



    }


}
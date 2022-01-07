//package io.github.zornx5.certificate;
//
//import io.github.zornx5.certificate.sm2.ECCUtil;
//import io.github.zornx5.certificate.sm2.SM2CertUtil;
//import io.github.zornx5.certificate.sm2.SM2PfxMaker;
//import io.github.zornx5.certificate.sm2.SM2PublicKey;
//import io.github.zornx5.certificate.sm2.SM2Util;
//import io.github.zornx5.certificate.sm2.SM2X509CertMaker;
//import io.github.zornx5.certificate.sm2.test.util.FileUtil;
//import io.github.zornx5.certificate.util.CommonUtil;
//import org.bouncycastle.asn1.ASN1Encoding;
//import org.bouncycastle.asn1.x500.X500Name;
//import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
//import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.pkcs.PKCS10CertificationRequest;
//import org.bouncycastle.pkcs.PKCS12PfxPdu;
//import org.junit.Assert;
//import org.junit.Test;
//
//import java.security.KeyPair;
//import java.security.PublicKey;
//import java.security.Security;
//import java.security.cert.X509Certificate;
//
//public class PfxMakerTest {
//    private static final String TEST_PFX_PASSWD = "12345678";
//    private static final String TEST_PFX_FILENAME = "target/test.pfx";
//
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }
//
//    @Test
//    public void testMakePfx() {
//        try {
//            KeyPair subKP = SM2Util.generateKeyPair();
//            X500Name subDN = SM2X509CertMakerTest.buildSubjectDN();
//            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
//                    (BCECPublicKey) subKP.getPublic());
//            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
//                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
//            SM2X509CertMaker certMaker = SM2X509CertMakerTest.buildCertMaker();
//            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);
//
//            SM2PfxMaker pfxMaker = new SM2PfxMaker();
//            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
//            PublicKey subPub = ECCUtil.createPublicKeyFromSubjectPublicKeyInfo(request.getSubjectPublicKeyInfo());
//            PKCS12PfxPdu pfx = pfxMaker.makePfx(subKP.getPrivate(), subPub, cert, TEST_PFX_PASSWD);
//            byte[] pfxDER = pfx.getEncoded(ASN1Encoding.DER);
//            FileUtil.writeFile(TEST_PFX_FILENAME, pfxDER);
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            Assert.fail();
//        }
//    }
//
//    @Test
//    public void testPfxSign() {
//        //先生成一个pfx
//        testMakePfx();
//
//        try {
//            byte[] pkcs12 = FileUtil.readFile(TEST_PFX_FILENAME);
//            BCECPublicKey publicKey = SM2CertUtil.getPublicKeyFromPfx(pkcs12, TEST_PFX_PASSWD);
//            BCECPrivateKey privateKey = SM2CertUtil.getPrivateKeyFromPfx(pkcs12, TEST_PFX_PASSWD);
//
//            String srcData = "1234567890123456789012345678901234567890";
//            byte[] sign = SM2Util.sign(privateKey, srcData.getBytes());
//            boolean flag = SM2Util.verify(publicKey, srcData.getBytes(), sign);
//            if (!flag) {
//                Assert.fail();
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            Assert.fail();
//        }
//    }
//}

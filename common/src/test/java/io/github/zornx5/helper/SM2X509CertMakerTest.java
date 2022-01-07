//package io.github.zornx5.certificate;
//
//import io.github.zornx5.certificate.sm2.ECCUtil;
//import io.github.zornx5.certificate.CertSNAllocator;
//import io.github.zornx5.certificate.util.CommonUtil;
//import io.github.zornx5.certificate.RandomSNAllocator;
//import io.github.zornx5.certificate.sm2.SM2PublicKey;
//import io.github.zornx5.certificate.sm2.SM2Util;
//import io.github.zornx5.certificate.sm2.SM2X509CertMaker;
//import io.github.zornx5.certificate.sm2.exception.InvalidX500NameException;
//import io.github.zornx5.certificate.sm2.test.util.FileUtil;
//import org.bouncycastle.asn1.x500.X500Name;
//import org.bouncycastle.asn1.x500.X500NameBuilder;
//import org.bouncycastle.asn1.x500.style.BCStyle;
//import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
//import org.bouncycastle.crypto.params.ECPublicKeyParameters;
//import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
//import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.junit.Assert;
//import org.junit.Test;
//
//import java.io.IOException;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.KeyPair;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.Security;
//import java.security.cert.X509Certificate;
//
//public class SM2X509CertMakerTest {
//
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }
//
//    public static void savePriKey(String filePath, BCECPrivateKey priKey, BCECPublicKey pubKey) throws IOException {
//        ECPrivateKeyParameters priKeyParam = ECCUtil.convertPrivateKeyToParameters(priKey);
//        ECPublicKeyParameters pubKeyParam = ECCUtil.convertPublicKeyToParameters(pubKey);
//        byte[] derPriKey = ECCUtil.convertECPrivateKeyToSEC1(priKeyParam, pubKeyParam);
//        FileUtil.writeFile(filePath, derPriKey);
//    }
//
//    public static X500Name buildSubjectDN() {
//        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.C, "CN");
//        builder.addRDN(BCStyle.O, "org.zz");
//        builder.addRDN(BCStyle.OU, "org.zz");
//        builder.addRDN(BCStyle.CN, "example.org");
//        builder.addRDN(BCStyle.EmailAddress, "abc@example.org");
//        return builder.build();
//    }
//
//    public static X500Name buildRootCADN() {
//        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.C, "CN");
//        builder.addRDN(BCStyle.O, "org.zz");
//        builder.addRDN(BCStyle.OU, "org.zz");
//        builder.addRDN(BCStyle.CN, "ZZ Root CA");
//        return builder.build();
//    }
//
//    public static SM2X509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException,
//            NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
//        X500Name issuerName = buildRootCADN();
//        KeyPair issKP = SM2Util.generateKeyPair();
//        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 20年
//        CertSNAllocator snAllocator = new RandomSNAllocator(); // 实际应用中可能需要使用数据库来保证证书序列号的唯一性。
//        return new SM2X509CertMaker(issKP, certExpire, issuerName, snAllocator);
//    }
//
//    @Test
//    public void testMakeCertificate() {
//        try {
//            KeyPair subKP = SM2Util.generateKeyPair();
//            X500Name subDN = buildSubjectDN();
//            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
//                    (BCECPublicKey) subKP.getPublic());
//            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
//                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
//            savePriKey("target/test.sm2.pri", (BCECPrivateKey) subKP.getPrivate(),
//                    (BCECPublicKey) subKP.getPublic());
//            SM2X509CertMaker certMaker = buildCertMaker();
//            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);
//            FileUtil.writeFile("target/test.sm2.cer", cert.getEncoded());
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            Assert.fail();
//        }
//    }
//}

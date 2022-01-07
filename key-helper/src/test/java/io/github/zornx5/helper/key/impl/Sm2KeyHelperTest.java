package io.github.zornx5.helper.key.impl;

import io.github.zornx5.helper.util.KeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Slf4j
public class Sm2KeyHelperTest {

    public final static String base64Sm2PrivateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgeZ6MVDl5JJfWmVBHLb4WXTgNdFSrKYbQL24hGA2ZRO6gCgYIKoEcz1UBgi2hRANCAARHpU/FkqCOKeh8Al2wlZBt0swhyAgfH16myQHil3emAuyLBt4vsso/7usIKuk38eyABDFI6/KG+68JH9HBuq/Y";
    public final static String base64Sm2PublicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAER6VPxZKgjinofAJdsJWQbdLMIcgIHx9epskB4pd3pgLsiwbeL7LKP+7rCCrpN/HsgAQxSOvyhvuvCR/Rwbqv2A==";
    private static PrivateKey rsaPrivateKey;
    private static PublicKey rsaPublicKey;
    private final Sm2KeyHelper helper = new Sm2KeyHelper();

    @BeforeClass
    public static void aftClass() {
        KeyPair rsaKeyPair = new RsaKeyHelper().generateKeyPair();
        Assert.assertNotNull(rsaKeyPair);
        rsaPrivateKey = rsaKeyPair.getPrivate();
        rsaPublicKey = rsaKeyPair.getPublic();
    }

    @Test
    public void generateKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        log.info("privateKey algorithm: [{}], format: [{}]", privateKey.getAlgorithm(), privateKey.getFormat());
        log.info("publicKey  algorithm: [{}], format: [{}]", publicKey.getAlgorithm(), publicKey.getFormat());
        log.info("privateKey base64 encode: [{}]", new String(Base64.getEncoder().encode(privateKey.getEncoded()), StandardCharsets.UTF_8));
        log.info("publicKey  base64 encode: [{}]", new String(Base64.getEncoder().encode(publicKey.getEncoded()), StandardCharsets.UTF_8));
        Assert.assertEquals("EC", privateKey.getAlgorithm());
        Assert.assertEquals("EC", publicKey.getAlgorithm());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());
        Assert.assertEquals("X.509", publicKey.getFormat());
        Assert.assertTrue(privateKey instanceof ECPrivateKey);
        Assert.assertTrue(publicKey instanceof ECPublicKey);
        Assert.assertTrue(privateKey instanceof BCECPrivateKey);
        Assert.assertTrue(publicKey instanceof BCECPublicKey);
    }

    @Test
    public void checkKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        KeyPair keyPair1 = null;
        try {
            keyPair1 = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(keyPair1);
        PrivateKey privateKey1 = keyPair1.getPrivate();
        PublicKey publicKey1 = keyPair1.getPublic();


        Assert.assertFalse(helper.checkKeyPair(privateKey, null));
        Assert.assertFalse(helper.checkKeyPair(null, publicKey));

        Assert.assertFalse(helper.checkKeyPair(rsaPrivateKey, rsaPublicKey));

        Assert.assertTrue(helper.checkKeyPair(privateKey, publicKey));
        Assert.assertTrue(helper.checkKeyPair(privateKey1, publicKey1));
        Assert.assertFalse(helper.checkKeyPair(privateKey, publicKey1));
        Assert.assertFalse(helper.checkKeyPair(privateKey1, publicKey));
    }

    @Test
    public void exchangePrivateKeyInfoAndPrivateKey() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKey2PrivateKeyInfo(privateKey);
        Assert.assertNotNull(privateKeyInfo);
        SubjectPublicKeyInfo subjectPublicKeyInfo = KeyUtil.convertPublicKey2SubjectPublicKeyInfo(publicKey);
        Assert.assertNotNull(subjectPublicKeyInfo);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertPrivateKeyInfo2PrivateKey(privateKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(convertPrivateKey);
        PublicKey convertPublicKey = null;
        try {
            convertPublicKey = helper.convertSubjectPublicKeyInfo2PublicKey(subjectPublicKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(convertPublicKey);

        Assert.assertEquals(privateKey, convertPrivateKey);
        Assert.assertEquals(publicKey, convertPublicKey);

    }

    @Test
    public void convertPrivateKey2PublicKey() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(keyPair);
        PublicKey publicKey = keyPair.getPublic();
        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertPrivateKey2PublicKey(keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(publicKeyConvert);
        Assert.assertArrayEquals(publicKey.getEncoded(), publicKeyConvert.getEncoded());

        PublicKey rsaPublicKey = null;
        try {
            rsaPublicKey = helper.convertPrivateKey2PublicKey(rsaPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNull(rsaPublicKey);
    }

    @Test
    public void exchangeBase64StringAndPrivateKey() {
        PrivateKey privateKey = null;
        String base64String = null;
        try {
            privateKey = helper.convertBase64String2PrivateKey(base64Sm2PrivateKey);
            base64String = KeyUtil.convertPrivateKey2Base64String(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(privateKey);
        Assert.assertEquals(base64Sm2PrivateKey, base64String);
    }

    @Test
    public void exchangeBase64StringAndPublicKey() {
        PublicKey publicKey = null;
        String base64String = null;
        try {
            publicKey = helper.convertBase64String2PublicKey(base64Sm2PublicKey);
            base64String = KeyUtil.convertPublicKey2Base64String(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(base64Sm2PublicKey, base64String);
    }

    @Test
    public void exchangePkcs8AndPkcs1() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String pkcs8Base64Private = KeyUtil.convertPrivateKey2Base64String(privateKey);
        String pkcs8Base64Public = KeyUtil.convertPublicKey2Base64String(publicKey);
        String pkcs1Base64Private = null;
        byte[] pkcs1Private = null;
        try {
            pkcs1Private = KeyUtil.convertPkcs8ToPkcs1(privateKey);
            pkcs1Base64Private = new String(Base64.getEncoder().encode(pkcs1Private));
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(pkcs1Base64Private);
        Assert.assertTrue(pkcs1Base64Private.trim().length() > 0);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertPkcs1ToPkcs8(pkcs1Private);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(convertPrivateKey);
        String convertPkcs8Base64PrivateKey = KeyUtil.convertPrivateKey2Base64String(privateKey);
        Assert.assertEquals(pkcs8Base64Private, convertPkcs8Base64PrivateKey);

        Assert.assertTrue(pkcs1Base64Private.trim().length() > 0);
        log.info(pkcs8Base64Private);
        log.info(pkcs1Base64Private);
        log.info(pkcs8Base64Public);
    }

    @Test
    public void convertToPem() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String pkcs8PrivateKeyPem = KeyUtil.convertToPkcs8Pem(privateKey);
        String pkcs8PublicKeyPem = KeyUtil.convertToPkcs8Pem(publicKey);
        String pkcs1PrivatePem = helper.convertToPkcs1Pem(privateKey);
        Assert.assertNotNull(pkcs8PrivateKeyPem);
        Assert.assertNotNull(pkcs8PublicKeyPem);
        Assert.assertNotNull(pkcs1PrivatePem);
    }

    @Test
    public void signAndVerify() {
        List<String> charsets = new ArrayList<>();
        charsets.add("GBK");
        charsets.add("GB2312");
        charsets.add("GB18030");
        charsets.add("UTF-8");
        List<String> contents = new ArrayList<>();
        contents.add("this is a text");
        contents.add("这是一段文本");
        contents.add(UUID.randomUUID().toString());
        for (String charset : charsets) {
            for (String content : contents) {
                signAndVerify(content, charset);
            }
        }
    }

    private void signAndVerify(String content, String charset) {
        String base64Sign = null;
        try {
            base64Sign = helper.sign(content, charset, base64Sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(base64Sign);
        log.info("签名长度: [{}] 输出为 [{}]", base64Sign.length(), base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(content, charset, base64Sm2PublicKey, base64Sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertTrue(verify);
    }

    @Test
    public void encryptAndDecrypt() {
        List<String> charsets = new ArrayList<>();
        charsets.add("GBK");
        charsets.add("GB2312");
        charsets.add("GB18030");
        charsets.add("UTF-8");
        List<String> contents = new ArrayList<>();
        contents.add("this is a text");
        contents.add("这是一段文本");
        contents.add(UUID.randomUUID().toString());
        for (String charset : charsets) {
            for (String content : contents) {
                encryptAndDecrypt(content, charset);
            }
        }
    }

    private void encryptAndDecrypt(String content, String charset) {
        String encrypt = null;
        try {
            encrypt = helper.encrypt(content, charset, base64Sm2PublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(encrypt);
        log.info("密文长度 [{}], 内容为 [{}]", encrypt.length(), encrypt);
        String decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, charset, base64Sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNotNull(decrypt);

        Assert.assertEquals(content, decrypt);
    }
}
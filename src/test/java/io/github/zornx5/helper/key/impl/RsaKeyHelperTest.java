/*
 * MIT License
 *
 * Copyright (c) 2022 ZornX5
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package io.github.zornx5.helper.key.impl;

import io.github.zornx5.helper.GlobalBouncyCastleProvider;
import io.github.zornx5.helper.constant.IHelperConstant;
import io.github.zornx5.helper.util.KeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Slf4j
public class RsaKeyHelperTest {

    public final static String base64RsaPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgWp/oM9yA4wH8kLoRagFUXjViCC0pS74xD93UMBZrvK86Gd9dlBmojJvRPmzg+ShcRo3EUgo92VUziC1HgCqBc0NQ2cYrGmooOh9ZeC82WpjC2Wzkn41z4VQLMs2JUMXkHOuzwhrdfYlWeJ6P0wzGIg0jB/JE54lmlPdrucKSZV6bYnri52TERaJZIct48uQsvZN9R197sL6g5lCqMcg+tzfHF8dOe1boArn2aAbHAVlyM04AqH6zE5I3hGgDxq6bruSP9tGbsIIAVRvRvrofIL2Gt+NSoXJI6bq3ISFuK8x+1dWfXp2iGiiIXcyUyT+Hmw2WshoUsRzOYK7JWzafAgMBAAECggEAF5vgKT7hezRxCW+BhajW00Yfk/RiOc9GDFEqtt/xnSElp2dBxLRWZsN0+YS4YRMuBw/4NWxix6Jk8fZdvEY5e9+tjIzTqWr1MEEGdpTEVrtV/HIonyyClgoZ5qAvNMVorWI4rbmpXOzruIh/x+sp2U4QIxU7bTuttiW+m+S4qfb5GiuVyEYb5F2X73QfqCGwiVMHmbVmaqibnR1VOO95lLJojZCDzVJBgam5bAGkEYi1CYUV+EUW4o30VGJmVOsqW4kjOYee1BLeveiQRv6Pnk6cqxu4KnARDxEPvUu7Nj2giCEHMWbnYoTONyE6On24yZWih64E1lm/B27sg+b0sQKBgQDRdkvPe3R4v5IBNQPse1ZegB8pgGXeBdMErdIVs9f6qAHJi0XI80fPckpiyAFJpI+Z/JYPy2xagPQ2cTPsQzw2CylGkZ6NP8ZrlaTiZ3PLtgaWH3YxQz8qNprrVMBX2PxI7P+0571wIPk47965QtGI9YuakiQe9G68lwlSjocpyQKBgQDD+y1vQvHem4TYzWk3hMdnzLuuEu2nWHE7nXbPvg88kHliPgVEzRJlbCLcezvxIZMitPDo2PUqi9Qy0/Vov06phcpJUIrupQrilKBM9DTXTiq1xwYtvp3bh1WASQBwYqykLtwrGywZ3C3IuqgpsYjU6gbZod7O1ec7Hug/r9GRJwKBgBwPySBG3de/coQO4jOwYmXOrF4XAY65IQgjcV3O9kRydarWqca+MQStvyF0whdnoIV0vXXoPt/xHsaca+RfLZXf8OuvXpp1zNNk/O4IBg9ol4FNPbxj0faJ0j9s30flngb3GVrXIR4AjOL/38raFNBQdR+ELKqo/JzvbyRMS/dhAoGBAKitzLpBnVni8yGDErdlQhe2ICdARWpOdg9AhV1ikUyocME87l38P4Qp4YtxSfNN2Yz6vYs8CS/YcAhbZJMGbZb8/1HA0AN86/R+xcXWPpC9x4bzSP8gXE/xmIa0znrsgvlBF+DGH1wWpRVqiohwNHxE/SZd6x6M/ttky7LdCfvrAoGAAfsL3AOil8yREyd4oOXKLGj2fnRuVudgFsGK3953qMz6Gh8yR1/kTc/aEHi7jHhvfZ6vGMLv8u7Q0ipKKEkCqmmOI9PqeS+kkSEHRbv0zmIM6WA8eyZKtf3UEhGoFuIvsz5U5qUZnaIsqp33/ufVu3himSdNc61/i67NUB9BpSc=";
    public final static String base64RsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoFqf6DPcgOMB/JC6EWoBVF41YggtKUu+MQ/d1DAWa7yvOhnfXZQZqIyb0T5s4PkoXEaNxFIKPdlVM4gtR4AqgXNDUNnGKxpqKDofWXgvNlqYwtls5J+Nc+FUCzLNiVDF5Bzrs8Ia3X2JVniej9MMxiINIwfyROeJZpT3a7nCkmVem2J64udkxEWiWSHLePLkLL2TfUdfe7C+oOZQqjHIPrc3xxfHTntW6AK59mgGxwFZcjNOAKh+sxOSN4RoA8aum67kj/bRm7CCAFUb0b66HyC9hrfjUqFySOm6tyEhbivMftXVn16dohooiF3MlMk/h5sNlrIaFLEczmCuyVs2nwIDAQAB";
    private static PrivateKey sm2PrivateKey;
    private static PublicKey sm2PublicKey;
    private final RsaKeyHelper helper = new RsaKeyHelper();

    @BeforeClass
    public static void beforeClass() {
        GlobalBouncyCastleProvider.setUseBouncyCastle(true);
        KeyPair sm2KeyPair = null;
        try {
            sm2KeyPair = new Sm2KeyHelper().generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(sm2KeyPair);
        sm2PrivateKey = sm2KeyPair.getPrivate();
        sm2PublicKey = sm2KeyPair.getPublic();
    }

    @Test
    public void generateKeyPair() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        log.info("privateKey algorithm: [{}], format: [{}]", privateKey.getAlgorithm(), privateKey.getFormat());
        log.info("publicKey  algorithm: [{}], format: [{}]", publicKey.getAlgorithm(), publicKey.getFormat());
        log.info("privateKey base64 encode: [{}]",
                new String(Base64.getEncoder().encode(privateKey.getEncoded()), StandardCharsets.UTF_8));
        log.info("publicKey  base64 encode: [{}]",
                new String(Base64.getEncoder().encode(publicKey.getEncoded()), StandardCharsets.UTF_8));
        Assert.assertEquals(IHelperConstant.RSA_ALGORITHM, privateKey.getAlgorithm());
        Assert.assertEquals(IHelperConstant.RSA_ALGORITHM, publicKey.getAlgorithm());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());
        Assert.assertEquals("X.509", publicKey.getFormat());
        Assert.assertTrue(privateKey instanceof RSAPrivateKey);
        Assert.assertTrue(publicKey instanceof RSAPublicKey);
        Assert.assertTrue(privateKey instanceof BCRSAPrivateKey);
        Assert.assertTrue(publicKey instanceof BCRSAPublicKey);
    }

    @Test
    public void generateKeyPairKeySize512() {
        KeyPair keyPair = helper.generateKeyPair(512);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(2048, keySize);
    }

    @Test
    public void generateKeyPairKeySize5120() {
        KeyPair keyPair = helper.generateKeyPair(5120);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(2048, keySize);
    }

    @Test
    public void generateKeyPairKeySize3000() {
        KeyPair keyPair = helper.generateKeyPair(3000);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(2048, keySize);
    }

    @Test
    public void getKeySize() {
        int keySize = 1024;
        KeyPair keyPair = helper.generateKeyPair(keySize);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        int privateKeySize = 0;
        int publicKeySize = 0;
        int sm2PrivateKeySize = 0;
        int sm2PublicKeySize = 0;
        try {
            privateKeySize = helper.getKeySize(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotEquals(0, privateKeySize);
        try {
            publicKeySize = helper.getKeySize(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotEquals(0, publicKeySize);
        try {
            sm2PrivateKeySize = helper.getKeySize(sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertEquals(0, sm2PrivateKeySize);
        try {
            sm2PublicKeySize = helper.getKeySize(sm2PublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertEquals(0, sm2PublicKeySize);
        Assert.assertEquals(keySize, privateKeySize, publicKeySize);
    }

    @Test
    public void getKeySizeError() {

    }

    @Test
    public void checkKeyPair() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        KeyPair keyPairOther = helper.generateKeyPair();
        Assert.assertNotNull(keyPairOther);
        PrivateKey privateKey1 = keyPairOther.getPrivate();
        PublicKey publicKey1 = keyPairOther.getPublic();


        Assert.assertFalse(helper.checkKeyPair(privateKey, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, publicKey));

        Assert.assertFalse(helper.checkKeyPair(sm2PrivateKey, sm2PublicKey));

        Assert.assertTrue(helper.checkKeyPair(privateKey, publicKey));
        Assert.assertTrue(helper.checkKeyPair(privateKey1, publicKey1));
        Assert.assertFalse(helper.checkKeyPair(privateKey, publicKey1));
        Assert.assertFalse(helper.checkKeyPair(privateKey1, publicKey));
    }

    @Test
    public void exchangePrivateKeyInfoAndPrivateKey() {
        KeyPair keyPair = helper.generateKeyPair();
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
            Assert.fail();
        }
        Assert.assertNotNull(convertPrivateKey);
        PublicKey convertPublicKey = null;
        try {
            convertPublicKey = helper.convertSubjectPublicKeyInfo2PublicKey(subjectPublicKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(convertPublicKey);

        Assert.assertEquals(privateKey, convertPrivateKey);
        Assert.assertEquals(publicKey, convertPublicKey);

    }

    @Test
    public void convertPrivateKey2PublicKey() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertPrivateKey2PublicKey(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKeyConvert);
        Assert.assertArrayEquals(publicKey.getEncoded(), publicKeyConvert.getEncoded());

        PublicKey sm2PublicKeyConvert = null;
        try {
            sm2PublicKeyConvert = helper.convertPrivateKey2PublicKey(sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNull(sm2PublicKeyConvert);
    }

    @Test
    public void exchangeBase64StringAndPrivateKey() {
        PrivateKey privateKey = null;
        String base64String = null;
        try {
            privateKey = helper.convertString2PrivateKey(base64RsaPrivateKey);
            base64String = KeyUtil.convertPrivateKey2Base64String(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(privateKey);
        Assert.assertEquals(base64RsaPrivateKey, base64String);
    }

    @Test
    public void exchangeBase64StringAndPublicKey() {
        PublicKey publicKey = null;
        String base64String = null;
        try {
            publicKey = helper.convertBase64String2PublicKey(base64RsaPublicKey);
            base64String = KeyUtil.convertPublicKey2Base64String(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(base64RsaPublicKey, base64String);
    }

    @Test
    public void exchangePkcs8AndPkcs1() {
        KeyPair keyPair = helper.generateKeyPair();
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
        } catch (IOException e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(pkcs1Base64Private);
        Assert.assertTrue(pkcs1Base64Private.trim().length() > 0);

        PrivateKey privateKey1 = null;
        try {
            privateKey1 = helper.convertPkcs1ToPkcs8(pkcs1Private);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(privateKey1);
        String pkcs8Base64Private1 = KeyUtil.convertPrivateKey2Base64String(privateKey);
        Assert.assertEquals(pkcs8Base64Private, pkcs8Base64Private1);

        Assert.assertTrue(pkcs1Base64Private.trim().length() > 0);
        log.info(pkcs8Base64Private);
        log.info(pkcs1Base64Private);
        log.info(pkcs8Base64Public);
    }

    @Test
    public void convertToPem() {
        KeyPair keyPair = helper.generateKeyPair();
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
            base64Sign = helper.sign(content, charset, base64RsaPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(base64Sign);
        log.info("签名长度: [{}] 输出为 [{}]", base64Sign.length(), base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(content, charset, base64RsaPublicKey, base64Sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
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
            encrypt = helper.encrypt(content, charset, base64RsaPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(encrypt);
        log.info("密文长度 [{}], 内容为 [{}]", encrypt.length(), encrypt);
        String decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, charset, base64RsaPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(decrypt);

        Assert.assertEquals(content, decrypt);
    }
}

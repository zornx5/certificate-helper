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
import io.github.zornx5.helper.exception.KeyHelperException;
import io.github.zornx5.helper.util.KeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.After;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

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

import static io.github.zornx5.helper.KeyContent.base64Sm2PrivateKey;
import static io.github.zornx5.helper.KeyContent.base64Sm2PublicKey;

@Slf4j
@RunWith(PowerMockRunner.class)
public class Sm2KeyHelperTest {

    private static PrivateKey rsaPrivateKey;
    private static PublicKey rsaPublicKey;
    private final Sm2KeyHelper helper = new Sm2KeyHelper();

    @BeforeClass
    public static void beforeClass() {
        GlobalBouncyCastleProvider.setUseBouncyCastle(true);
        KeyPair rsaKeyPair = new RsaKeyHelper().generateKeyPair();
        Assert.assertNotNull(rsaKeyPair);
        rsaPrivateKey = rsaKeyPair.getPrivate();
        rsaPublicKey = rsaKeyPair.getPublic();
    }

    @After
    public void setUp() {
        helper.setEcCurve(IHelperConstant.SM2_EC_CURVE);
    }

    @Test
    public void generateKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
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

    @Test(expected = KeyHelperException.class)
    public void generateKeyPairError() {
        helper.setEcCurve("ecCurve");
        System.out.println(helper.getEcCurve());
        helper.generateKeyPair();
    }

    @Test
    public void checkKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        KeyPair keyPair1 = null;
        try {
            keyPair1 = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(keyPair1);
        PrivateKey privateKey1 = keyPair1.getPrivate();
        PublicKey publicKey1 = keyPair1.getPublic();


        Assert.assertFalse(helper.checkKeyPair(privateKey, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, publicKey));

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
            Assert.fail();
        }
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKey2PrivateKeyInfo(privateKey);
        Assert.assertNotNull(privateKeyInfo);
        SubjectPublicKeyInfo subjectPublicKeyInfo = KeyUtil.convertToSubjectPublicKeyInfo(publicKey);
        Assert.assertNotNull(subjectPublicKeyInfo);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertToPrivateKey(privateKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(convertPrivateKey);
        PublicKey convertPublicKey = null;
        try {
            convertPublicKey = helper.convertToPublicKey(subjectPublicKeyInfo);
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
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(keyPair);
        PublicKey publicKey = keyPair.getPublic();
        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertToPublicKey(keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKeyConvert);
        Assert.assertArrayEquals(publicKey.getEncoded(), publicKeyConvert.getEncoded());

        PublicKey rsaPublicKey = null;
        try {
            rsaPublicKey = helper.convertToPublicKey(rsaPrivateKey);
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
            privateKey = helper.convertToPrivateKey(base64Sm2PrivateKey);
            base64String = KeyUtil.convertPrivateKey2Base64String(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(privateKey);
        Assert.assertEquals(base64Sm2PrivateKey, base64String);
    }

    @Test
    public void exchangeBase64StringAndPublicKey() {
        PublicKey publicKey = null;
        String base64String = null;
        try {
            publicKey = helper.convertToPublicKey(base64Sm2PublicKey);
            base64String = KeyUtil.convertPublicKey2Base64String(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
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
            Assert.fail();
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
            Assert.fail();
        }
        Assert.assertNotNull(pkcs1Base64Private);
        Assert.assertTrue(pkcs1Base64Private.trim().length() > 0);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertPrivateKeyPkcs1ToPkcs8(pkcs1Private);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
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
            Assert.fail();
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
            Assert.fail();
        }
        Assert.assertNotNull(base64Sign);
        log.info("签名长度: [{}] 输出为 [{}]", base64Sign.length(), base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(content, charset, base64Sm2PublicKey, base64Sign);
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
            encrypt = helper.encrypt(content, charset, base64Sm2PublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(encrypt);
        log.info("密文长度 [{}], 内容为 [{}]", encrypt.length(), encrypt);
        String decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, charset, base64Sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(decrypt);

        Assert.assertEquals(content, decrypt);
    }
}

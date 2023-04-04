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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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

import static io.github.zornx5.helper.KeyTestContent.base64EcPrivateKey;
import static io.github.zornx5.helper.KeyTestContent.base64EcPublicKey;

@Slf4j
public class ECKeyHelperTest {

    private static PrivateKey rsaPrivateKey;
    private static PublicKey rsaPublicKey;

    private final EcKeyHelper helper = new EcKeyHelper();

    @BeforeAll
    public static void init() {
        GlobalBouncyCastleProvider.setUseBouncyCastle(true);
        KeyPair rsaKeyPair = new RsaKeyHelper().generateKeyPair();
        Assertions.assertNotNull(rsaKeyPair);
        rsaPrivateKey = rsaKeyPair.getPrivate();
        rsaPublicKey = rsaKeyPair.getPublic();
    }

    @AfterEach
    public void setUp() {
        helper.setEcCurve(IHelperConstant.EC_DEFAULT_CURVE);
        log.debug("EC 曲线：{}", helper.getEcCurve());
    }

    @Test
    public void generateKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        log.info("privateKey algorithm: [{}], format: [{}]", privateKey.getAlgorithm(), privateKey.getFormat());
        log.info("publicKey  algorithm: [{}], format: [{}]", publicKey.getAlgorithm(), publicKey.getFormat());
        log.info("privateKey base64 encode: [{}]", new String(Base64.getEncoder().encode(privateKey.getEncoded()), StandardCharsets.UTF_8));
        log.info("publicKey  base64 encode: [{}]", new String(Base64.getEncoder().encode(publicKey.getEncoded()), StandardCharsets.UTF_8));
        Assertions.assertEquals("EC", privateKey.getAlgorithm());
        Assertions.assertEquals("EC", publicKey.getAlgorithm());
        Assertions.assertEquals("PKCS#8", privateKey.getFormat());
        Assertions.assertEquals("X.509", publicKey.getFormat());
        Assertions.assertTrue(privateKey instanceof ECPrivateKey);
        Assertions.assertTrue(publicKey instanceof ECPublicKey);
        Assertions.assertTrue(privateKey instanceof BCECPrivateKey);
        Assertions.assertTrue(publicKey instanceof BCECPublicKey);
    }

    @Test
    public void generateKeyPairError() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.setEcCurve("ecCurve");
            helper.generateKeyPair();
        });

    }

    @Test
    public void checkKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        KeyPair keyPair1 = null;
        try {
            keyPair1 = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(keyPair1);
        PrivateKey privateKey1 = keyPair1.getPrivate();
        PublicKey publicKey1 = keyPair1.getPublic();


        Assertions.assertFalse(helper.checkKeyPair(privateKey, (PublicKey) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, publicKey));

        Assertions.assertFalse(helper.checkKeyPair(rsaPrivateKey, rsaPublicKey));

        Assertions.assertTrue(helper.checkKeyPair(privateKey, publicKey));
        Assertions.assertTrue(helper.checkKeyPair(privateKey1, publicKey1));
        Assertions.assertFalse(helper.checkKeyPair(privateKey, publicKey1));
        Assertions.assertFalse(helper.checkKeyPair(privateKey1, publicKey));
    }

    @Test
    public void exchangePrivateKeyInfoAndPrivateKey() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKeyToPrivateKeyInfo(privateKey);
        Assertions.assertNotNull(privateKeyInfo);
        SubjectPublicKeyInfo subjectPublicKeyInfo = KeyUtil.convertPublicKeyToSubjectPublicKeyInfo(publicKey);
        Assertions.assertNotNull(subjectPublicKeyInfo);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertToPrivateKey(privateKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(convertPrivateKey);
        PublicKey convertPublicKey = null;
        try {
            convertPublicKey = helper.convertToPublicKey(subjectPublicKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(convertPublicKey);

        Assertions.assertEquals(privateKey, convertPrivateKey);
        Assertions.assertEquals(publicKey, convertPublicKey);

    }

    @Test
    public void convertPrivateKey2PublicKey() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(keyPair);
        PublicKey publicKey = keyPair.getPublic();
        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertToPublicKey(keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKeyConvert);
        Assertions.assertArrayEquals(publicKey.getEncoded(), publicKeyConvert.getEncoded());
    }

    @Test
    public void convertPrivateKey2PublicKeyError() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPublicKey(rsaPrivateKey);
        });
    }

    @Test
    public void exchangeBase64StringAndPrivateKey() {
        PrivateKey privateKey = null;
        String base64String = null;
        try {
            privateKey = helper.convertToPrivateKey(base64EcPrivateKey);
            base64String = KeyUtil.convertPrivateKeyToBase64String(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(privateKey);
        Assertions.assertEquals(base64EcPrivateKey, base64String);
    }

    @Test
    public void exchangeBase64StringAndPublicKey() {
        PublicKey publicKey = null;
        String base64String = null;
        try {
            publicKey = helper.convertToPublicKey(base64EcPublicKey);
            base64String = KeyUtil.convertPublicKeyToBase64String(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKey);
        Assertions.assertEquals(base64EcPublicKey, base64String);
    }

    @Test
    public void exchangePkcs8AndPkcs1() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String pkcs8Base64Private = KeyUtil.convertPrivateKeyToBase64String(privateKey);
        String pkcs8Base64Public = KeyUtil.convertPublicKeyToBase64String(publicKey);
        String pkcs1Base64Private = null;
        byte[] pkcs1Private = null;
        try {
            pkcs1Private = KeyUtil.convertPrivateKeyToPkcs1(privateKey);
            pkcs1Base64Private = new String(Base64.getEncoder().encode(pkcs1Private));
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(pkcs1Base64Private);
        Assertions.assertTrue(pkcs1Base64Private.trim().length() > 0);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertPrivateKeyPkcs1ToPkcs8(pkcs1Private);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assertions.assertNull(convertPrivateKey);
    }

    @Test
    public void convertToPem() {
        KeyPair keyPair = null;
        try {
            keyPair = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String pkcs8PrivateKeyPem = KeyUtil.convertPrivateKeyToPkcs8Pem(privateKey);
        String pkcs8PublicKeyPem = KeyUtil.convertPublicKeyToPkcs8Pem(publicKey);
        String pkcs1PrivatePem = helper.convertToPkcs1Pem(privateKey);
        Assertions.assertNotNull(pkcs8PrivateKeyPem);
        Assertions.assertNotNull(pkcs8PublicKeyPem);
        Assertions.assertNotNull(pkcs1PrivatePem);
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
            base64Sign = helper.sign(content, charset, base64EcPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(content, charset, base64EcPublicKey, base64Sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertTrue(verify);
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
            encrypt = helper.encrypt(content, charset, base64EcPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(encrypt);
        String decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, charset, base64EcPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(decrypt);

        Assertions.assertEquals(content, decrypt);
    }
}

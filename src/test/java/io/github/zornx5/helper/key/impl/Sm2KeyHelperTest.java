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
import io.github.zornx5.helper.util.Base64Util;
import io.github.zornx5.helper.util.KeyUtil;
import io.github.zornx5.helper.util.PemUtil;
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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static io.github.zornx5.helper.KeyContent.base64RsaPrivateKey;
import static io.github.zornx5.helper.KeyContent.base64RsaPublicKey;
import static io.github.zornx5.helper.KeyContent.base64Sm2PrivateKey;
import static io.github.zornx5.helper.KeyContent.base64Sm2PublicKey;
import static io.github.zornx5.helper.KeyContent.pemRsaPrivateKey;
import static io.github.zornx5.helper.KeyContent.pemRsaPublicKey;
import static io.github.zornx5.helper.KeyContent.pemSm2PrivateKey;
import static io.github.zornx5.helper.KeyContent.pemSm2PublicKey;

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

        Assert.assertEquals(IHelperConstant.EC_ALGORITHM, privateKey.getAlgorithm());
        Assert.assertEquals(IHelperConstant.EC_ALGORITHM, publicKey.getAlgorithm());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());
        Assert.assertEquals(IHelperConstant.X509_CERTIFICATE_TYPE, publicKey.getFormat());
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
    public void checkKeyPairWithNull() {
        Assert.assertFalse(helper.checkKeyPair(null, (String) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair(null, (byte[]) null));
    }

    @Test
    public void checkKeyPairWithString() {
        Assert.assertTrue(helper.checkKeyPair(base64Sm2PrivateKey, base64Sm2PublicKey));
        Assert.assertTrue(helper.checkKeyPair(pemSm2PrivateKey, pemSm2PublicKey));
        Assert.assertTrue(helper.checkKeyPair(base64Sm2PrivateKey, pemSm2PublicKey));
        Assert.assertTrue(helper.checkKeyPair(pemSm2PrivateKey, base64Sm2PublicKey));
    }

    @Test
    public void checkKeyPairWithErrorAlgorithm() {
        Assert.assertFalse(helper.checkKeyPair(base64RsaPrivateKey, base64RsaPublicKey));
        Assert.assertFalse(helper.checkKeyPair(pemRsaPrivateKey, pemRsaPublicKey));
        Assert.assertFalse(helper.checkKeyPair(base64RsaPrivateKey, pemRsaPublicKey));
        Assert.assertFalse(helper.checkKeyPair(pemRsaPrivateKey, base64RsaPublicKey));

        Assert.assertFalse(helper.checkKeyPair(rsaPrivateKey, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, rsaPublicKey));
        Assert.assertFalse(helper.checkKeyPair(rsaPrivateKey, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, rsaPublicKey));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair(rsaPrivateKey, rsaPublicKey));
        Assert.assertFalse(helper.checkKeyPair(rsaPrivateKey.getEncoded(), rsaPublicKey.getEncoded()));
        Assert.assertFalse(helper.checkKeyPair(null, rsaPublicKey.getEncoded()));
        Assert.assertFalse(helper.checkKeyPair(rsaPrivateKey.getEncoded(), null));
    }

    @Test
    public void checkKeyPair() {
        KeyPair keyPair = null;
        KeyPair keyPairAnother = null;
        try {
            keyPair = helper.generateKeyPair();
            keyPairAnother = helper.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPairAnother);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKeyAnother = keyPairAnother.getPrivate();
        PublicKey publicKeyAnother = keyPairAnother.getPublic();


        Assert.assertTrue(helper.checkKeyPair(privateKey, helper.convertToSubjectPublicKeyInfo(publicKey)));
        Assert.assertTrue(helper.checkKeyPair(helper.convertToPrivateKeyInfo(privateKey), publicKey));
        Assert.assertTrue(helper.checkKeyPair(helper.convertToPrivateKeyInfo(privateKey), helper.convertToSubjectPublicKeyInfo(publicKey)));
        Assert.assertTrue(helper.checkKeyPair(privateKey, publicKey));
        Assert.assertTrue(helper.checkKeyPair(privateKey.getEncoded(), publicKey.getEncoded()));
        Assert.assertTrue(helper.checkKeyPair(privateKeyAnother, publicKeyAnother));
        Assert.assertTrue(helper.checkKeyPair(privateKeyAnother.getEncoded(), publicKeyAnother.getEncoded()));

        Assert.assertFalse(helper.checkKeyPair(null, base64Sm2PublicKey));
        Assert.assertFalse(helper.checkKeyPair(base64Sm2PrivateKey, null));

        Assert.assertFalse(helper.checkKeyPair(privateKey, publicKeyAnother));
        Assert.assertFalse(helper.checkKeyPair(privateKeyAnother, publicKey));

        Assert.assertFalse(helper.checkKeyPair(privateKey, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, publicKey));

        Assert.assertFalse(helper.checkKeyPair(privateKey, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, publicKey));
        Assert.assertFalse(helper.checkKeyPair(privateKey, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, publicKey));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair(null, publicKey.getEncoded()));
        Assert.assertFalse(helper.checkKeyPair(privateKey.getEncoded(), null));
    }

    @Test
    public void exchangePrivateKeyInfoAndPrivateKey() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();

        PrivateKeyInfo privateKeyInfo = helper.convertToPrivateKeyInfo(privateKey);
        Assert.assertNotNull(privateKeyInfo);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertToPrivateKey(privateKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(convertPrivateKey);

        Assert.assertEquals(privateKey, convertPrivateKey);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPrivateKeyInfoWithNull() {
        helper.convertToPrivateKeyInfo(null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPrivateKeyWithStringNull() {
        helper.convertToPrivateKey((String) null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPrivateKeyWithPrivateKeyInfoNull() {
        helper.convertToPrivateKey((PrivateKeyInfo) null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPrivateKeyWithDataNull() {
        helper.convertToPrivateKey((byte[]) null);
    }

    @Test
    public void exchangeSubjectPublicKeyInfoAndPublicKey() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PublicKey publicKey = keyPair.getPublic();

        SubjectPublicKeyInfo subjectPublicKeyInfo = helper.convertToSubjectPublicKeyInfo(publicKey);
        Assert.assertNotNull(subjectPublicKeyInfo);

        PublicKey convertPublicKey = null;
        try {
            convertPublicKey = helper.convertToPublicKey(subjectPublicKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(convertPublicKey);

        Assert.assertEquals(publicKey, convertPublicKey);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToSubjectPublicKeyInfoWithNull() {
        helper.convertToSubjectPublicKeyInfo(null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPublicKeyWithStringNull() {
        helper.convertToPublicKey((String) null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPublicKeyWithPrivateKeyInfoNull() {
        helper.convertToPublicKey((SubjectPublicKeyInfo) null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPublicKeyWithDataNull() {
        helper.convertToPublicKey((byte[]) null);
    }

    @Test
    public void convertPrivateKey2PublicKey2() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertPrivateKeyToPublicKey(privateKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKeyConvert);
        Assert.assertEquals(publicKey, publicKeyConvert);
    }

    @Test
    public void convertPrivateKey2PublicKey() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertToPublicKey(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKeyConvert);
        Assert.assertEquals(publicKey, publicKeyConvert);
    }

    @Test(expected = KeyHelperException.class)
    public void convertPrivateKey2PublicKeyWithPrivateKeyNull() {
        helper.convertToPublicKey((PrivateKey) null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertPrivateKey2PublicKeyWithDataNull() {
        helper.convertToPublicKey((byte[]) null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertPrivateKey2PublicKeyWithErrorAlgorithm() {
        helper.convertToPublicKey(rsaPrivateKey);
    }

    @Test
    public void exchangeBase64StringAndPrivateKey() {
        PrivateKey privateKey = null;
        String base64String = null;
        try {
            privateKey = helper.convertToPrivateKey(base64Sm2PrivateKey);
            base64String = helper.convertToString(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(privateKey);
        Assert.assertNotNull(base64String);
        Assert.assertEquals(base64Sm2PrivateKey, base64String);
    }

    @Test(expected = KeyHelperException.class)
    public void convertKeyToStringPrivateKeyNull() {
        helper.convertToString((PrivateKey) null);
    }

    @Test
    public void exchangePemStringAndPrivateKey() {
        PrivateKey privateKey = null;
        String pemString = null;
        try {
            privateKey = helper.convertToPrivateKey(pemSm2PrivateKey);
            pemString = helper.convertToPem(privateKey);
            PrivateKey privateKey1 = helper.convertToPrivateKey(pemString);
            String convertToPem = helper.convertToPem(privateKey1);
            Assert.assertEquals(pemString,convertToPem);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(privateKey);
        Assert.assertNotNull(pemString);
        Assert.assertEquals(pemSm2PrivateKey, pemString);
    }

    @Test(expected = KeyHelperException.class)
    public void convertKeyToPemStringPrivateKeyNull() {
        helper.convertToPem((PrivateKey) null);
    }

    @Test
    public void exchangeBase64StringAndPublicKey() {
        PublicKey publicKey = null;
        String base64String = null;
        try {
            publicKey = helper.convertToPublicKey(base64Sm2PublicKey);
            base64String = helper.convertToString(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(base64Sm2PublicKey, base64String);
    }

    @Test(expected = KeyHelperException.class)
    public void convertKeyToStringPublicKeyNull() {
        helper.convertToString((PublicKey) null);
    }

    @Test
    public void exchangePemStringAndPublicKey() {
        PublicKey publicKey = null;
        String pemString = null;
        try {
            publicKey = helper.convertToPublicKey(pemSm2PublicKey);
            pemString = helper.convertToPem(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(pemSm2PublicKey, pemString);
    }

    @Test(expected = KeyHelperException.class)
    public void convertKeyToPemStringPublicKeyNull() {
        helper.convertToPem((PublicKey) null);
    }

    @Test
    public void exchangePkcs8AndPkcs1() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);

        PrivateKey privateKey = keyPair.getPrivate();

        String pkcs1String = helper.convertToPkcs1String(privateKey);

        PrivateKey convertPrivateKey = helper.convertPrivateKeyPkcs1ToPkcs8(Base64Util.decode2byte(pkcs1String));
        Assert.assertTrue(privateKey instanceof ECPrivateKey);
        Assert.assertTrue(convertPrivateKey instanceof ECPrivateKey);

        // TODO 这里转换回来似乎有点问题
        Assert.assertEquals(((ECPrivateKey) privateKey).getS(), ((ECPrivateKey) convertPrivateKey).getS());
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPkcs1String() {
        helper.convertToPkcs1String(null);
    }

    @Test(expected = KeyHelperException.class)
    public void convertPrivateKeyPkcs1ToPkcs8() {
        helper.convertPrivateKeyPkcs1ToPkcs8(null);
    }
    @Test(expected = KeyHelperException.class)
    public void convertPrivateKeyPkcs1ToPkcs8WithError() {
        helper.convertPrivateKeyPkcs1ToPkcs8(Base64Util.decode2byte(base64RsaPrivateKey));
    }

    @Test
    public void convertToPkcs1Pem() {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();

        String pkcs1PrivatePem = helper.convertToPkcs1Pem(privateKey);
        Assert.assertNotNull(pkcs1PrivatePem);
    }

    @Test(expected = KeyHelperException.class)
    public void convertToPkcs1PemWithNull() {
        helper.convertToPkcs1Pem(null);
    }

    @Test
    public void signAndVerify() {
        List<String> charsets = new ArrayList<>();
        charsets.add("GBK");
        charsets.add("GB2312");
        charsets.add("GB18030");
        charsets.add("UTF-8");
        List<String> plainTexts = new ArrayList<>();
        plainTexts.add("this is a text");
        plainTexts.add("这是一段文本");
        plainTexts.add(UUID.randomUUID().toString());

        for (String plainText : plainTexts) {
            for (String charset : charsets) {
                signAndVerify(plainText, charset);
            }
            signAndVerify1(plainText.getBytes());
            signAndVerify2(plainText.getBytes());
        }
    }

    @Test(expected = KeyHelperException.class)
    public void signError() {
        helper.sign(null, null, null);
    }

    @Test(expected = KeyHelperException.class)
    public void signError1() {
        helper.sign(null, (PrivateKey) null);
    }

    @Test(expected = KeyHelperException.class)
    public void signError2() {
        helper.sign(null, (byte[]) null);
    }

    @Test(expected = KeyHelperException.class)
    public void verifyError() {
        helper.verify(null, null, null, null);
    }

    @Test(expected = KeyHelperException.class)
    public void verifyError1() {
        helper.verify(null, (PublicKey) null, null);
    }

    @Test(expected = KeyHelperException.class)
    public void verifyError2() {
        helper.verify(null, (byte[]) null, null);
    }

    @Test
    public void encryptAndDecrypt() {
        List<String> charsets = new ArrayList<>();
        charsets.add("GBK");
        charsets.add("GB2312");
        charsets.add("GB18030");
        charsets.add("UTF-8");
        List<String> plainTexts = new ArrayList<>();
        plainTexts.add("this is a text");
        plainTexts.add("这是一段文本");
        plainTexts.add(UUID.randomUUID().toString());

        for (String plainText : plainTexts) {
            for (String charset : charsets) {
                encryptAndDecrypt(plainText, charset);
            }
            encryptAndDecrypt1(plainText.getBytes());
            encryptAndDecrypt2(plainText.getBytes());
        }
    }

    @Test(expected = KeyHelperException.class)
    public void encryptError() {
        helper.encrypt(null, null, null);
    }

    @Test(expected = KeyHelperException.class)
    public void encryptError1() {
        helper.encrypt(null, (PublicKey) null);
    }

    @Test(expected = KeyHelperException.class)
    public void encryptError2() {
        helper.encrypt(null, (byte[]) null);
    }

    @Test(expected = KeyHelperException.class)
    public void decryptError() {
        helper.decrypt(null, null, null);
    }

    @Test(expected = KeyHelperException.class)
    public void decryptError1() {
        helper.decrypt(null, (PrivateKey) null);
    }

    @Test(expected = KeyHelperException.class)
    public void decryptError2() {
        helper.decrypt(null, (byte[]) null);
    }

    private void signAndVerify(String plainText, String charset) {
        String base64Sign = null;
        try {
            base64Sign = helper.sign(plainText, charset, base64Sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(plainText, charset, base64Sm2PublicKey, base64Sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertTrue(verify);
    }

    private void signAndVerify1(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);

        byte[] sign = null;
        try {
            sign = helper.sign(plainText, keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(sign);

        boolean verify = false;
        try {
            verify = helper.verify(plainText, keyPair.getPublic(), sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertTrue(verify);
    }

    private void signAndVerify2(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);

        byte[] sign = null;
        try {
            sign = helper.sign(plainText, keyPair.getPrivate().getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(sign);

        boolean verify = false;
        try {
            verify = helper.verify(plainText, keyPair.getPublic().getEncoded(), sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertTrue(verify);
    }

    private void encryptAndDecrypt(String plainText, String charset) {
        String encrypt = null;
        try {
            encrypt = helper.encrypt(plainText, charset, base64Sm2PublicKey);
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

        Assert.assertEquals(plainText, decrypt);
    }

    private void encryptAndDecrypt1(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        byte[] encrypt = null;
        try {
            encrypt = helper.encrypt(plainText, keyPair.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(encrypt);
        byte[] decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(decrypt);

        Assert.assertArrayEquals(plainText, decrypt);
    }

    private void encryptAndDecrypt2(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assert.assertNotNull(keyPair);
        byte[] encrypt = null;
        try {
            encrypt = helper.encrypt(plainText, keyPair.getPublic().getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(encrypt);
        byte[] decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, keyPair.getPrivate().getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(decrypt);

        Assert.assertArrayEquals(plainText, decrypt);
    }
}

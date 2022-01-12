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
import io.github.zornx5.helper.key.IKeyHelper;
import io.github.zornx5.helper.util.Base64Util;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
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
public class RsaKeyHelperTest {

    private static PrivateKey sm2PrivateKey;
    private static PublicKey sm2PublicKey;
    private final IKeyHelper helper = new RsaKeyHelper();

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

        Assert.assertEquals(IHelperConstant.RSA_ALGORITHM, privateKey.getAlgorithm());
        Assert.assertEquals(IHelperConstant.RSA_ALGORITHM, publicKey.getAlgorithm());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());
        Assert.assertEquals(IHelperConstant.X509_CERTIFICATE_TYPE, publicKey.getFormat());
        Assert.assertTrue(privateKey instanceof RSAPrivateKey);
        Assert.assertTrue(publicKey instanceof RSAPublicKey);
        Assert.assertTrue(privateKey instanceof BCRSAPrivateKey);
        Assert.assertTrue(publicKey instanceof BCRSAPublicKey);

        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithNegativeKeySize() {
        KeyPair keyPair = helper.generateKeyPair(-100);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithKeySize512() {
        KeyPair keyPair = helper.generateKeyPair(512);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithKeySize5120() {
        KeyPair keyPair = helper.generateKeyPair(5120);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithKeySize3000() {
        KeyPair keyPair = helper.generateKeyPair(3000);
        Assert.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assert.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
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
        try {
            privateKeySize = new RsaKeyHelper().getKeySize(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotEquals(0, privateKeySize);
        try {
            publicKeySize = new RsaKeyHelper().getKeySize(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotEquals(0, publicKeySize);
        Assert.assertEquals(keySize, privateKeySize, publicKeySize);
    }

    @Test
    public void getPrivateKeySizeError() {
        int sm2PrivateKeySize = 0;
        try {
            sm2PrivateKeySize = new RsaKeyHelper().getKeySize(sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertEquals(0, sm2PrivateKeySize);
    }

    @Test
    public void getPublicKeySizeError() {
        int sm2PublicKeySize = 0;
        try {
            sm2PublicKeySize = new RsaKeyHelper().getKeySize(sm2PublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertEquals(0, sm2PublicKeySize);
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
        Assert.assertTrue(helper.checkKeyPair(base64RsaPrivateKey, base64RsaPublicKey));
        Assert.assertTrue(helper.checkKeyPair(pemRsaPrivateKey, pemRsaPublicKey));
        Assert.assertTrue(helper.checkKeyPair(base64RsaPrivateKey, pemRsaPublicKey));
        Assert.assertTrue(helper.checkKeyPair(pemRsaPrivateKey, base64RsaPublicKey));
    }

    @Test
    public void checkKeyPairWithErrorAlgorithm() {
        Assert.assertFalse(helper.checkKeyPair(base64Sm2PrivateKey, base64Sm2PublicKey));
        Assert.assertFalse(helper.checkKeyPair(pemSm2PrivateKey, pemSm2PublicKey));
        Assert.assertFalse(helper.checkKeyPair(base64Sm2PrivateKey, pemSm2PublicKey));
        Assert.assertFalse(helper.checkKeyPair(pemSm2PrivateKey, base64Sm2PublicKey));

        Assert.assertFalse(helper.checkKeyPair(sm2PrivateKey, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, sm2PublicKey));
        Assert.assertFalse(helper.checkKeyPair(sm2PrivateKey, (PublicKey) null));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, sm2PublicKey));
        Assert.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assert.assertFalse(helper.checkKeyPair(sm2PrivateKey, sm2PublicKey));
        Assert.assertFalse(helper.checkKeyPair(sm2PrivateKey.getEncoded(), sm2PublicKey.getEncoded()));
        Assert.assertFalse(helper.checkKeyPair(null, sm2PublicKey.getEncoded()));
        Assert.assertFalse(helper.checkKeyPair(sm2PrivateKey.getEncoded(), null));
    }

    @Test
    public void checkKeyPair() {
        KeyPair keyPair = helper.generateKeyPair();
        KeyPair keyPairAnother = helper.generateKeyPair();

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

        Assert.assertFalse(helper.checkKeyPair(null, base64RsaPublicKey));
        Assert.assertFalse(helper.checkKeyPair(base64RsaPrivateKey, null));

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
        helper.convertToPublicKey(sm2PrivateKey);
    }

    @Test
    public void exchangeBase64StringAndPrivateKey() {
        PrivateKey privateKey = null;
        String base64String = null;
        try {
            privateKey = helper.convertToPrivateKey(base64RsaPrivateKey);
            base64String = helper.convertToString(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(privateKey);
        Assert.assertNotNull(base64String);
        Assert.assertEquals(base64RsaPrivateKey, base64String);
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
            privateKey = helper.convertToPrivateKey(pemRsaPrivateKey);
            pemString = helper.convertToPem(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(privateKey);
        Assert.assertNotNull(pemString);
        Assert.assertEquals(pemRsaPrivateKey, pemString);
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
            publicKey = helper.convertToPublicKey(base64RsaPublicKey);
            base64String = helper.convertToString(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(base64RsaPublicKey, base64String);
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
            publicKey = helper.convertToPublicKey(pemRsaPublicKey);
            pemString = helper.convertToPem(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(pemRsaPublicKey, pemString);
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
        Assert.assertTrue(privateKey instanceof RSAPrivateKey);
        Assert.assertTrue(convertPrivateKey instanceof RSAPrivateKey);

        // TODO 这里转换回来似乎有点问题
        Assert.assertEquals(((RSAPrivateKey) privateKey).getModulus(), ((RSAPrivateKey) convertPrivateKey).getModulus());
        Assert.assertEquals(((RSAPrivateKey) privateKey).getPrivateExponent(), ((RSAPrivateKey) convertPrivateKey).getPrivateExponent());
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
        helper.convertPrivateKeyPkcs1ToPkcs8(Base64Util.decode2byte(base64Sm2PrivateKey));
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
            base64Sign = helper.sign(plainText, charset, base64RsaPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
        Assert.assertNotNull(base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(plainText, charset, base64RsaPublicKey, base64Sign);
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
            encrypt = helper.encrypt(plainText, charset, base64RsaPublicKey);
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

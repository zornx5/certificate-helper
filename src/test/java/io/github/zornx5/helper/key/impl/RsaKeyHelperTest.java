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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.github.zornx5.helper.KeyTestContent.base64RsaPrivateKey;
import static io.github.zornx5.helper.KeyTestContent.base64RsaPublicKey;
import static io.github.zornx5.helper.KeyTestContent.base64Sm2PrivateKey;
import static io.github.zornx5.helper.KeyTestContent.base64Sm2PublicKey;
import static io.github.zornx5.helper.KeyTestContent.pemRsaPrivateKey;
import static io.github.zornx5.helper.KeyTestContent.pemRsaPublicKey;
import static io.github.zornx5.helper.KeyTestContent.pemSm2PrivateKey;
import static io.github.zornx5.helper.KeyTestContent.pemSm2PublicKey;

@Slf4j
public class RsaKeyHelperTest {

    private static PrivateKey sm2PrivateKey;
    private static PublicKey sm2PublicKey;
    private final IKeyHelper helper = new RsaKeyHelper();

    @BeforeAll
    public static void init() {
        GlobalBouncyCastleProvider.setUseBouncyCastle(true);
        KeyPair sm2KeyPair = null;
        try {
            sm2KeyPair = new Sm2KeyHelper().generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(sm2KeyPair);
        sm2PrivateKey = sm2KeyPair.getPrivate();
        sm2PublicKey = sm2KeyPair.getPublic();
    }

    @Test
    public void generateKeyPair() {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Assertions.assertEquals(IHelperConstant.RSA_ALGORITHM, privateKey.getAlgorithm());
        Assertions.assertEquals(IHelperConstant.RSA_ALGORITHM, publicKey.getAlgorithm());
        Assertions.assertEquals("PKCS#8", privateKey.getFormat());
        Assertions.assertEquals(IHelperConstant.X509_CERTIFICATE_TYPE, publicKey.getFormat());
        Assertions.assertTrue(privateKey instanceof RSAPrivateKey);
        Assertions.assertTrue(publicKey instanceof RSAPublicKey);
        Assertions.assertTrue(privateKey instanceof BCRSAPrivateKey);
        Assertions.assertTrue(publicKey instanceof BCRSAPublicKey);

        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assertions.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithNegativeKeySize() {
        KeyPair keyPair = helper.generateKeyPair(-100);
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assertions.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithKeySize512() {
        KeyPair keyPair = helper.generateKeyPair(512);
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assertions.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithKeySize5120() {
        KeyPair keyPair = helper.generateKeyPair(5120);
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assertions.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void generateKeyPairWithKeySize3000() {
        KeyPair keyPair = helper.generateKeyPair(3000);
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        int keySize = ((BCRSAPrivateKey) privateKey).getModulus().toString(2).length();
        Assertions.assertEquals(IHelperConstant.RSA_DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    public void getKeySize() {
        int keySize = 1024;
        KeyPair keyPair = helper.generateKeyPair(keySize);
        Assertions.assertNotNull(keyPair);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        int privateKeySize = 0;
        int publicKeySize = 0;
        try {
            privateKeySize = new RsaKeyHelper().getKeySize(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotEquals(0, privateKeySize);
        try {
            publicKeySize = new RsaKeyHelper().getKeySize(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotEquals(0, publicKeySize);
        Assertions.assertEquals(keySize, privateKeySize, publicKeySize);
    }

    @Test
    public void getPrivateKeySizeError() {
        int sm2PrivateKeySize = 0;
        try {
            sm2PrivateKeySize = new RsaKeyHelper().getKeySize(sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assertions.assertEquals(0, sm2PrivateKeySize);
    }

    @Test
    public void getPublicKeySizeError() {
        int sm2PublicKeySize = 0;
        try {
            sm2PublicKeySize = new RsaKeyHelper().getKeySize(sm2PublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assertions.assertEquals(0, sm2PublicKeySize);
    }

    @Test
    public void checkKeyPairWithNull() {
        Assertions.assertFalse(helper.checkKeyPair(null, (String) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, (PublicKey) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, (PublicKey) null));
        Assertions.assertFalse(helper.checkKeyPair(null, (byte[]) null));
    }

    @Test
    public void checkKeyPairWithString() {
        Assertions.assertTrue(helper.checkKeyPair(base64RsaPrivateKey, base64RsaPublicKey));
        Assertions.assertTrue(helper.checkKeyPair(pemRsaPrivateKey, pemRsaPublicKey));
        Assertions.assertTrue(helper.checkKeyPair(base64RsaPrivateKey, pemRsaPublicKey));
        Assertions.assertTrue(helper.checkKeyPair(pemRsaPrivateKey, base64RsaPublicKey));
    }

    @Test
    public void checkKeyPairWithErrorAlgorithm() {
        Assertions.assertFalse(helper.checkKeyPair(base64Sm2PrivateKey, base64Sm2PublicKey));
        Assertions.assertFalse(helper.checkKeyPair(pemSm2PrivateKey, pemSm2PublicKey));
        Assertions.assertFalse(helper.checkKeyPair(base64Sm2PrivateKey, pemSm2PublicKey));
        Assertions.assertFalse(helper.checkKeyPair(pemSm2PrivateKey, base64Sm2PublicKey));

        Assertions.assertFalse(helper.checkKeyPair(sm2PrivateKey, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, sm2PublicKey));
        Assertions.assertFalse(helper.checkKeyPair(sm2PrivateKey, (PublicKey) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, sm2PublicKey));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair(sm2PrivateKey, sm2PublicKey));
        Assertions.assertFalse(helper.checkKeyPair(sm2PrivateKey.getEncoded(), sm2PublicKey.getEncoded()));
        Assertions.assertFalse(helper.checkKeyPair(null, sm2PublicKey.getEncoded()));
        Assertions.assertFalse(helper.checkKeyPair(sm2PrivateKey.getEncoded(), null));
    }

    @Test
    public void checkKeyPair() {
        KeyPair keyPair = helper.generateKeyPair();
        KeyPair keyPairAnother = helper.generateKeyPair();

        Assertions.assertNotNull(keyPair);
        Assertions.assertNotNull(keyPairAnother);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKeyAnother = keyPairAnother.getPrivate();
        PublicKey publicKeyAnother = keyPairAnother.getPublic();

        Assertions.assertTrue(helper.checkKeyPair(privateKey, helper.convertToSubjectPublicKeyInfo(publicKey)));
        Assertions.assertTrue(helper.checkKeyPair(helper.convertToPrivateKeyInfo(privateKey), publicKey));
        Assertions.assertTrue(helper.checkKeyPair(helper.convertToPrivateKeyInfo(privateKey), helper.convertToSubjectPublicKeyInfo(publicKey)));
        Assertions.assertTrue(helper.checkKeyPair(privateKey, publicKey));
        Assertions.assertTrue(helper.checkKeyPair(privateKey.getEncoded(), publicKey.getEncoded()));
        Assertions.assertTrue(helper.checkKeyPair(privateKeyAnother, publicKeyAnother));
        Assertions.assertTrue(helper.checkKeyPair(privateKeyAnother.getEncoded(), publicKeyAnother.getEncoded()));

        Assertions.assertFalse(helper.checkKeyPair(null, base64RsaPublicKey));
        Assertions.assertFalse(helper.checkKeyPair(base64RsaPrivateKey, null));

        Assertions.assertFalse(helper.checkKeyPair(privateKey, publicKeyAnother));
        Assertions.assertFalse(helper.checkKeyPair(privateKeyAnother, publicKey));

        Assertions.assertFalse(helper.checkKeyPair(privateKey, (PublicKey) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, publicKey));

        Assertions.assertFalse(helper.checkKeyPair(privateKey, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, publicKey));
        Assertions.assertFalse(helper.checkKeyPair(privateKey, (PublicKey) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, publicKey));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair(null, publicKey.getEncoded()));
        Assertions.assertFalse(helper.checkKeyPair(privateKey.getEncoded(), null));
    }

    @Test
    public void exchangePrivateKeyInfoAndPrivateKey() {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();

        PrivateKeyInfo privateKeyInfo = helper.convertToPrivateKeyInfo(privateKey);
        Assertions.assertNotNull(privateKeyInfo);

        PrivateKey convertPrivateKey = null;
        try {
            convertPrivateKey = helper.convertToPrivateKey(privateKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(convertPrivateKey);

        Assertions.assertEquals(privateKey, convertPrivateKey);
    }

    @Test
    public void convertToPrivateKeyInfoWithNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPrivateKeyInfo(null);
        });
    }

    @Test
    public void convertToPrivateKeyWithStringNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPrivateKey((String) null);
        });
    }

    @Test
    public void convertToPrivateKeyWithPrivateKeyInfoNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPrivateKey((PrivateKeyInfo) null);
        });
    }

    @Test
    public void convertToPrivateKeyWithDataNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPrivateKey((byte[]) null);
        });
    }

    @Test
    public void exchangeSubjectPublicKeyInfoAndPublicKey() {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        PublicKey publicKey = keyPair.getPublic();

        SubjectPublicKeyInfo subjectPublicKeyInfo = helper.convertToSubjectPublicKeyInfo(publicKey);
        Assertions.assertNotNull(subjectPublicKeyInfo);

        PublicKey convertPublicKey = null;
        try {
            convertPublicKey = helper.convertToPublicKey(subjectPublicKeyInfo);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(convertPublicKey);

        Assertions.assertEquals(publicKey, convertPublicKey);
    }

    @Test
    public void convertToSubjectPublicKeyInfoWithNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToSubjectPublicKeyInfo(null);
        });
    }

    @Test
    public void convertToPublicKeyWithStringNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPublicKey((String) null);
        });
    }

    @Test
    public void convertToPublicKeyWithPrivateKeyInfoNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPublicKey((SubjectPublicKeyInfo) null);
        });
    }

    @Test
    public void convertToPublicKeyWithDataNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPublicKey((byte[]) null);
        });
    }

    @Test
    public void convertPrivateKey2PublicKey2() {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertPrivateKeyToPublicKey(privateKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKeyConvert);
        Assertions.assertEquals(publicKey, publicKeyConvert);
    }

    @Test
    public void convertPrivateKey2PublicKey() {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        PublicKey publicKeyConvert = null;
        try {
            publicKeyConvert = helper.convertToPublicKey(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKeyConvert);
        Assertions.assertEquals(publicKey, publicKeyConvert);
    }

    @Test
    public void convertPrivateKey2PublicKeyWithPrivateKeyNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPublicKey((PrivateKey) null);
        });
    }

    @Test
    public void convertPrivateKey2PublicKeyWithDataNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPublicKey((byte[]) null);
        });
    }

    @Test
    public void convertPrivateKey2PublicKeyWithErrorAlgorithm() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPublicKey(sm2PrivateKey);
        });
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
            Assertions.fail();
        }
        Assertions.assertNotNull(privateKey);
        Assertions.assertNotNull(base64String);
        Assertions.assertEquals(base64RsaPrivateKey, base64String);
    }

    @Test
    public void convertKeyToStringPrivateKeyNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToString((PrivateKey) null);
        });
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
            Assertions.fail();
        }
        Assertions.assertNotNull(privateKey);
        Assertions.assertNotNull(pemString);
        Assertions.assertEquals(pemRsaPrivateKey, pemString);
    }

    @Test
    public void convertKeyToPemStringPrivateKeyNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPem((PrivateKey) null);
        });
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
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKey);
        Assertions.assertEquals(base64RsaPublicKey, base64String);
    }

    @Test
    public void convertKeyToStringPublicKeyNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToString((PublicKey) null);
        });
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
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKey);
        Assertions.assertEquals(pemRsaPublicKey, pemString);
    }

    @Test
    public void convertKeyToPemStringPublicKeyNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPem((PublicKey) null);
        });
    }

    @Test
    public void exchangePkcs8AndPkcs1() {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);

        PrivateKey privateKey = keyPair.getPrivate();

        String pkcs1String = helper.convertToPkcs1String(privateKey);

        PrivateKey convertPrivateKey = helper.convertPrivateKeyPkcs1ToPkcs8(Base64Util.decode2byte(pkcs1String));
        Assertions.assertTrue(privateKey instanceof RSAPrivateKey);
        Assertions.assertTrue(convertPrivateKey instanceof RSAPrivateKey);

        // TODO 这里转换回来似乎有点问题
        Assertions.assertEquals(((RSAPrivateKey) privateKey).getModulus(), ((RSAPrivateKey) convertPrivateKey).getModulus());
        Assertions.assertEquals(((RSAPrivateKey) privateKey).getPrivateExponent(), ((RSAPrivateKey) convertPrivateKey).getPrivateExponent());
    }

    @Test
    public void convertToPkcs1String() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPkcs1String(null);
        });
    }

    @Test
    public void convertPrivateKeyPkcs1ToPkcs8() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertPrivateKeyPkcs1ToPkcs8(null);
        });
    }

    @Test
    public void convertPrivateKeyPkcs1ToPkcs8WithError() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertPrivateKeyPkcs1ToPkcs8(Base64Util.decode2byte(base64Sm2PrivateKey));
        });
    }

    @Test
    public void convertToPkcs1Pem() {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();

        String pkcs1PrivatePem = helper.convertToPkcs1Pem(privateKey);
        Assertions.assertNotNull(pkcs1PrivatePem);
    }

    @Test
    public void convertToPkcs1PemWithNull() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.convertToPkcs1Pem(null);
        });
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

    @Test
    public void signError() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.sign(null, null, null);
        });
    }

    @Test
    public void signError1() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.sign(null, (PrivateKey) null);
        });
    }

    @Test
    public void signError2() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.sign(null, (byte[]) null);
        });
    }

    @Test
    public void verifyError() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.verify(null, null, null, null);
        });
    }

    @Test
    public void verifyError1() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.verify(null, (PublicKey) null, null);
        });
    }

    @Test
    public void verifyError2() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.verify(null, (byte[]) null, null);
        });
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

    @Test
    public void encryptError() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.encrypt(null, null, null);
        });
    }

    @Test
    public void encryptError1() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.encrypt(null, (PublicKey) null);
        });
    }

    @Test
    public void encryptError2() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.encrypt(null, (byte[]) null);
        });
    }

    @Test
    public void decryptError() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.decrypt(null, null, null);
        });
    }

    @Test
    public void decryptError1() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.decrypt(null, (PrivateKey) null);
        });
    }

    @Test
    public void decryptError2() {
        Throwable exception = Assertions.assertThrows(KeyHelperException.class, () -> {
            helper.decrypt(null, (byte[]) null);
        });
    }

    private void signAndVerify(String plainText, String charset) {
        String base64Sign = null;
        try {
            base64Sign = helper.sign(plainText, charset, base64RsaPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(plainText, charset, base64RsaPublicKey, base64Sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertTrue(verify);
    }

    private void signAndVerify1(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);

        byte[] sign = null;
        try {
            sign = helper.sign(plainText, keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(sign);

        boolean verify = false;
        try {
            verify = helper.verify(plainText, keyPair.getPublic(), sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertTrue(verify);
    }

    private void signAndVerify2(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);

        byte[] sign = null;
        try {
            sign = helper.sign(plainText, keyPair.getPrivate().getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(sign);

        boolean verify = false;
        try {
            verify = helper.verify(plainText, keyPair.getPublic().getEncoded(), sign);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertTrue(verify);
    }

    private void encryptAndDecrypt(String plainText, String charset) {
        String encrypt = null;
        try {
            encrypt = helper.encrypt(plainText, charset, base64RsaPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(encrypt);
        String decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, charset, base64RsaPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(decrypt);

        Assertions.assertEquals(plainText, decrypt);
    }

    private void encryptAndDecrypt1(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        byte[] encrypt = null;
        try {
            encrypt = helper.encrypt(plainText, keyPair.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(encrypt);
        byte[] decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(decrypt);

        Assertions.assertArrayEquals(plainText, decrypt);
    }

    private void encryptAndDecrypt2(byte[] plainText) {
        KeyPair keyPair = helper.generateKeyPair();
        Assertions.assertNotNull(keyPair);
        byte[] encrypt = null;
        try {
            encrypt = helper.encrypt(plainText, keyPair.getPublic().getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(encrypt);
        byte[] decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, keyPair.getPrivate().getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(decrypt);

        Assertions.assertArrayEquals(plainText, decrypt);
    }
}

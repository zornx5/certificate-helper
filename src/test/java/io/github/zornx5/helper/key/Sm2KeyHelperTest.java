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

package io.github.zornx5.helper.key;

import io.github.zornx5.helper.GlobalBouncyCastleProvider;
import io.github.zornx5.helper.constant.HelperConstant;
import io.github.zornx5.helper.exception.KeyHelperException;
import io.github.zornx5.helper.util.Base64Util;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
public class Sm2KeyHelperTest {

    private static PrivateKey rsaPrivateKey;
    private static PublicKey rsaPublicKey;
    private final Sm2KeyHelper helper = new Sm2KeyHelper();

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
        helper.setEcCurve(HelperConstant.SM2_EC_CURVE);
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

        Assertions.assertEquals(HelperConstant.EC_ALGORITHM, privateKey.getAlgorithm());
        Assertions.assertEquals(HelperConstant.EC_ALGORITHM, publicKey.getAlgorithm());
        Assertions.assertEquals("PKCS#8", privateKey.getFormat());
        Assertions.assertEquals(HelperConstant.X509_CERTIFICATE_TYPE, publicKey.getFormat());
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
        Assertions.assertTrue(helper.checkKeyPair(base64Sm2PrivateKey, base64Sm2PublicKey));
        Assertions.assertTrue(helper.checkKeyPair(pemSm2PrivateKey, pemSm2PublicKey));
        Assertions.assertTrue(helper.checkKeyPair(base64Sm2PrivateKey, pemSm2PublicKey));
        Assertions.assertTrue(helper.checkKeyPair(pemSm2PrivateKey, base64Sm2PublicKey));
    }

    @Test
    public void checkKeyPairWithErrorAlgorithm() {
        Assertions.assertFalse(helper.checkKeyPair(base64RsaPrivateKey, base64RsaPublicKey));
        Assertions.assertFalse(helper.checkKeyPair(pemRsaPrivateKey, pemRsaPublicKey));
        Assertions.assertFalse(helper.checkKeyPair(base64RsaPrivateKey, pemRsaPublicKey));
        Assertions.assertFalse(helper.checkKeyPair(pemRsaPrivateKey, base64RsaPublicKey));

        Assertions.assertFalse(helper.checkKeyPair(rsaPrivateKey, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKeyInfo) null, rsaPublicKey));
        Assertions.assertFalse(helper.checkKeyPair(rsaPrivateKey, (PublicKey) null));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, rsaPublicKey));
        Assertions.assertFalse(helper.checkKeyPair((PrivateKey) null, (SubjectPublicKeyInfo) null));
        Assertions.assertFalse(helper.checkKeyPair(rsaPrivateKey, rsaPublicKey));
        Assertions.assertFalse(helper.checkKeyPair(rsaPrivateKey.getEncoded(), rsaPublicKey.getEncoded()));
        Assertions.assertFalse(helper.checkKeyPair(null, rsaPublicKey.getEncoded()));
        Assertions.assertFalse(helper.checkKeyPair(rsaPrivateKey.getEncoded(), null));
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
            Assertions.fail();
        }
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

        Assertions.assertFalse(helper.checkKeyPair(null, base64Sm2PublicKey));
        Assertions.assertFalse(helper.checkKeyPair(base64Sm2PrivateKey, null));

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
            helper.convertToPublicKey(rsaPrivateKey);
        });
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
            Assertions.fail();
        }
        Assertions.assertNotNull(privateKey);
        Assertions.assertNotNull(base64String);
        Assertions.assertEquals(base64Sm2PrivateKey, base64String);
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
            privateKey = helper.convertToPrivateKey(pemSm2PrivateKey);
            pemString = helper.convertToPem(privateKey);
            PrivateKey privateKey1 = helper.convertToPrivateKey(pemString);
            String convertToPem = helper.convertToPem(privateKey1);
            Assertions.assertEquals(pemString, convertToPem);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(privateKey);
        Assertions.assertNotNull(pemString);
        Assertions.assertEquals(pemSm2PrivateKey, pemString);
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
            publicKey = helper.convertToPublicKey(base64Sm2PublicKey);
            base64String = helper.convertToString(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKey);
        Assertions.assertEquals(base64Sm2PublicKey, base64String);
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
            publicKey = helper.convertToPublicKey(pemSm2PublicKey);
            pemString = helper.convertToPem(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(publicKey);
        Assertions.assertEquals(pemSm2PublicKey, pemString);
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
        Assertions.assertTrue(privateKey instanceof ECPrivateKey);
        Assertions.assertTrue(convertPrivateKey instanceof ECPrivateKey);

        // TODO 这里转换回来似乎有点问题
        Assertions.assertEquals(((ECPrivateKey) privateKey).getS(), ((ECPrivateKey) convertPrivateKey).getS());
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
            base64Sign = helper.sign(plainText, charset, base64Sm2PrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(base64Sign);
        boolean verify = false;
        try {
            verify = helper.verify(plainText, charset, base64Sm2PublicKey, base64Sign);
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
            encrypt = helper.encrypt(plainText, charset, base64Sm2PublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(encrypt);
        log.info("密文长度 [{}], 内容为 [{}]", encrypt.length(), encrypt);
        String decrypt = null;
        try {
            decrypt = helper.decrypt(encrypt, charset, base64Sm2PrivateKey);
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

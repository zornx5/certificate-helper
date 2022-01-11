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

package io.github.zornx5.helper.maker;

import io.github.zornx5.helper.key.KeyHelperManager;
import io.github.zornx5.helper.util.CertificateUtil;
import io.github.zornx5.helper.util.KeyUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;


public class Pkcs12MakerTest {
    private static final char[] TEST_P12_PASSWD = "12345678".toCharArray();
    private static final String TEST_P12_FILENAME = "target/test.p12";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMakePkcs12() {
        try {
            KeyPair keyPair = KeyHelperManager.getByName("sm2").generateKeyPair();
            X500Name subDN = X509CertificateMakerTest.buildSubjectDN();
            byte[] csr = CertificateUtil.generateCertificationRequest(subDN, keyPair.getPrivate()).getEncoded();
            X509CertificateMaker certMaker = X509CertificateMakerTest.buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            Pkcs12Maker pkcs12Maker = new Pkcs12Maker();
            KeyStore pkcs12 = pkcs12Maker.makePkcs12(keyPair.getPrivate(), cert, TEST_P12_PASSWD);
            try (OutputStream os = Files.newOutputStream(Paths.get(TEST_P12_FILENAME),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                pkcs12.store(os, TEST_P12_PASSWD);
            }


            KeyStore ks = CertificateUtil.getKeyStore();
            try (InputStream is = Files.newInputStream(Paths.get(TEST_P12_FILENAME),
                    StandardOpenOption.READ)) {
                ks.load(is, TEST_P12_PASSWD);
            }

            PrivateKey privateKey = (BCECPrivateKey) ks.getKey("User Key", TEST_P12_PASSWD);
            X509Certificate cert1 = (X509Certificate) ks.getCertificate("User Key");

            byte[] srcData = "1234567890123456789012345678901234567890".getBytes();

            // create signature
            Signature sign = KeyUtil.getSignature("SM3withSM2");
            sign.initSign(privateKey);
            sign.update(srcData);
            byte[] signatureValue = sign.sign();

            // verify signature
            Signature verify = KeyUtil.getSignature("SM3withSM2");
            verify.initVerify(cert1);
            verify.update(srcData);
            boolean sigValid = verify.verify(signatureValue);
            Assert.assertTrue("signature validation result", sigValid);

        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

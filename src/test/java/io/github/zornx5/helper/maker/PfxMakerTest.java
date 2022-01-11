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

import io.github.zornx5.helper.key.IKeyHelper;
import io.github.zornx5.helper.key.KeyHelperManager;
import io.github.zornx5.helper.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class PfxMakerTest {
    private static final String TEST_PFX_PASSWD = "12345678";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMakePfx() {
        try {
            IKeyHelper helper = KeyHelperManager.getByName("Sm2");
            KeyPair keyPair = helper.generateKeyPair();
            X500Name subDN = X509CertificateMakerTest.buildSubjectDN();
            byte[] csr = CertificateUtil.generateCertificationRequest(subDN, keyPair.getPrivate()).getEncoded();
            X509CertificateMaker certMaker = X509CertificateMakerTest.buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            PfxMaker pfxMaker = new PfxMaker();
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
            PublicKey publicKey = helper.convertSubjectPublicKeyInfo2PublicKey(request.getSubjectPublicKeyInfo());
            PKCS12PfxPdu pfx = pfxMaker.makePfx(keyPair.getPrivate(), publicKey, cert, TEST_PFX_PASSWD);
            byte[] pkcs12 = pfx.getEncoded(ASN1Encoding.DER);

            BCECPublicKey publicKey1 = (BCECPublicKey) CertificateUtil.getPublicKeyFromPfx(pkcs12, TEST_PFX_PASSWD);
            BCECPrivateKey privateKey = (BCECPrivateKey) CertificateUtil.getPrivateKeyFromPfx(pkcs12, TEST_PFX_PASSWD);

            String srcData = "1234567890123456789012345678901234567890";
            byte[] sign = helper.sign(srcData.getBytes(), privateKey);
            boolean flag = helper.verify(srcData.getBytes(), publicKey1, sign);
            if (!flag) {
                Assert.fail();
            }


        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

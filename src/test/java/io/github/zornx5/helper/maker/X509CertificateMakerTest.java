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

import io.github.zornx5.helper.CertificateSerialNumberAllocator;
import io.github.zornx5.helper.impl.RandomCertificateSerialNumberAllocatorImpl;
import io.github.zornx5.helper.key.KeyHelperManager;
import io.github.zornx5.helper.util.CertificateUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class X509CertificateMakerTest {

    public static X500Name buildSubjectDN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "example.org");
        builder.addRDN(BCStyle.EmailAddress, "abc@example.org");
        return builder.build();
    }

    public static X500Name buildRootCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "ZZ Root CA");
        return builder.build();
    }

    public static X509CertificateMaker buildCertMaker() {
        X500Name issuerName = buildRootCADN();
        KeyPair issKP = KeyHelperManager.getByName("sm2").generateKeyPair();
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 20年
        // 实际应用中可能需要使用数据库来保证证书序列号的唯一性。
        CertificateSerialNumberAllocator snAllocator = new RandomCertificateSerialNumberAllocatorImpl();
        return new X509CertificateMaker(issKP, certExpire, issuerName, snAllocator);
    }

    @Test
    public void testMakeCertificate() {
        try {
            KeyPair keyPair = KeyHelperManager.getByName("Sm2").generateKeyPair();
            X500Name subDN = buildSubjectDN();

            byte[] csr = CertificateUtil.generateCertificationRequest(subDN, keyPair.getPrivate()).getEncoded();

            X509CertificateMaker certMaker = buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);
            Assert.assertNotNull(cert);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}

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

package io.github.zornx5.helper.util;

import io.github.zornx5.helper.key.EcKeyHelper;
import io.github.zornx5.helper.key.RsaKeyHelper;
import io.github.zornx5.helper.key.Sm2KeyHelper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Locale;

@Slf4j
public class CertificateUtilTest {

    private static PrivateKey sm2PrivateKey;
    private static PrivateKey rsaPrivateKey;
    private static PrivateKey ecPrivateKey;
    private static X500Name issuer;
    private static X500Name subject;

    @BeforeAll
    public static void aftClass() {
        KeyPair sm2KeyPair = null;
        try {
            sm2KeyPair = new Sm2KeyHelper().generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(sm2KeyPair);
        sm2PrivateKey = sm2KeyPair.getPrivate();

        KeyPair rsaKeyPair = new RsaKeyHelper().generateKeyPair();
        Assertions.assertNotNull(rsaKeyPair);
        rsaPrivateKey = rsaKeyPair.getPrivate();

        KeyPair ecKeyPair = null;
        try {
            ecKeyPair = new EcKeyHelper().generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(ecKeyPair);
        ecPrivateKey = ecKeyPair.getPrivate();

        X500NameBuilder issuerBuilder = new X500NameBuilder();
        issuerBuilder.addRDN(BCStyle.CN, "CN");
        issuerBuilder.addRDN(BCStyle.O, "getOrganization");
        issuerBuilder.addRDN(BCStyle.OU, "getOrganizationUnit");
        issuerBuilder.addRDN(BCStyle.C, "getCountry");
        issuerBuilder.addRDN(BCStyle.ST, "getState");
        issuerBuilder.addRDN(BCStyle.L, "getLocality");
        issuerBuilder.addRDN(BCStyle.STREET, "getStreet");
        issuerBuilder.addRDN(BCStyle.E, "getCommonName");
        issuer = issuerBuilder.build();
        Assertions.assertNotNull(issuer);

        X500NameBuilder subjectBuilder = new X500NameBuilder();
        subjectBuilder.addRDN(BCStyle.CN, "CN");
        subjectBuilder.addRDN(BCStyle.O, "getOrganization");
        subjectBuilder.addRDN(BCStyle.OU, "getOrganizationUnit");
        subjectBuilder.addRDN(BCStyle.C, "getCountry");
        subjectBuilder.addRDN(BCStyle.ST, "getState");
        subjectBuilder.addRDN(BCStyle.L, "getLocality");
        subjectBuilder.addRDN(BCStyle.STREET, "getStreet");
        subjectBuilder.addRDN(BCStyle.E, "getCommonName");
        subject = subjectBuilder.build();
    }

    @Test
    public void generateAndCheckCertificationRequest() {
        PKCS10CertificationRequest sm2SelfSignedCsr = getCsr(issuer, sm2PrivateKey);

        PKCS10CertificationRequest ecSelfSignedCsr = getCsr(issuer, ecPrivateKey);

        PKCS10CertificationRequest rsaSelfSignedCsr = getCsr(issuer, rsaPrivateKey);

        // 正例
        Assertions.assertTrue(CertificateUtil.checkCertificationRequest(sm2SelfSignedCsr, sm2PrivateKey));
        Assertions.assertTrue(CertificateUtil.checkCertificationRequest(ecSelfSignedCsr, ecPrivateKey));
        Assertions.assertTrue(CertificateUtil.checkCertificationRequest(rsaSelfSignedCsr, rsaPrivateKey));

        // 反例
        Assertions.assertFalse(CertificateUtil.checkCertificationRequest(sm2SelfSignedCsr, ecPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificationRequest(sm2SelfSignedCsr, rsaPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificationRequest(ecSelfSignedCsr, sm2PrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificationRequest(ecSelfSignedCsr, rsaPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificationRequest(rsaSelfSignedCsr, sm2PrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificationRequest(rsaSelfSignedCsr, ecPrivateKey));
    }

    @Test
    public void generateAndCheckSelfSignedCertificate() {
        PKCS10CertificationRequest sm2SelfSignedCsr = getCsr(issuer, sm2PrivateKey);
        Certificate sm2SelfSignedCertificate = getSelfSignedCertificate(sm2SelfSignedCsr, sm2PrivateKey);

        PKCS10CertificationRequest ecSelfSignedCsr = getCsr(issuer, ecPrivateKey);
        Certificate ecSelfSignedCertificate = getSelfSignedCertificate(ecSelfSignedCsr, ecPrivateKey);


        PKCS10CertificationRequest rsaSelfSignedCsr = getCsr(issuer, rsaPrivateKey);
        Certificate rsaSelfSignedCertificate = getSelfSignedCertificate(rsaSelfSignedCsr, rsaPrivateKey);

        // 正例
        Assertions.assertTrue(CertificateUtil.checkCertificate(sm2SelfSignedCertificate, sm2PrivateKey));
        Assertions.assertTrue(CertificateUtil.checkCertificate(ecSelfSignedCertificate, ecPrivateKey));
        Assertions.assertTrue(CertificateUtil.checkCertificate(rsaSelfSignedCertificate, rsaPrivateKey));

        // 反例
        Assertions.assertFalse(CertificateUtil.checkCertificate(sm2SelfSignedCertificate, ecPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(sm2SelfSignedCertificate, rsaPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(ecSelfSignedCertificate, sm2PrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(ecSelfSignedCertificate, rsaPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(rsaSelfSignedCertificate, sm2PrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(rsaSelfSignedCertificate, ecPrivateKey));
    }

    @Test
    public void generateAndCheckCertificate() {
        PKCS10CertificationRequest sm2SelfSignedCsr = getCsr(issuer, sm2PrivateKey);
        Certificate sm2SelfSignedCertificate = getSelfSignedCertificate(sm2SelfSignedCsr, sm2PrivateKey);

        PKCS10CertificationRequest sm2Csr = getCsr(subject, sm2PrivateKey);
        Certificate sm2Certificate = getCertificate(sm2SelfSignedCertificate, sm2Csr, sm2PrivateKey);

        PKCS10CertificationRequest ecSelfSignedCsr = getCsr(issuer, ecPrivateKey);
        Certificate ecSelfSignedCertificate = getSelfSignedCertificate(ecSelfSignedCsr, ecPrivateKey);

        PKCS10CertificationRequest ecCsr = getCsr(subject, ecPrivateKey);
        Certificate ecCertificate = getCertificate(ecSelfSignedCertificate, ecCsr, ecPrivateKey);

        PKCS10CertificationRequest rsaSelfSignedCsr = getCsr(issuer, rsaPrivateKey);
        Certificate rsaSelfSignedCertificate = getSelfSignedCertificate(rsaSelfSignedCsr, rsaPrivateKey);

        PKCS10CertificationRequest rsaCsr = getCsr(subject, rsaPrivateKey);
        Certificate rsaCertificate = getCertificate(rsaSelfSignedCertificate, rsaCsr, rsaPrivateKey);

        try {
            log.info(PemUtil.writePemString("CERTIFICATE", rsaCertificate.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
            Assertions.fail();
        }

        // 正例
        Assertions.assertTrue(CertificateUtil.checkCertificate(sm2Certificate, sm2Csr, sm2PrivateKey));
        Assertions.assertTrue(CertificateUtil.checkCertificate(ecCertificate, ecCsr, ecPrivateKey));
        Assertions.assertTrue(CertificateUtil.checkCertificate(rsaCertificate, rsaCsr, rsaPrivateKey));

        // 反例
        Assertions.assertFalse(CertificateUtil.checkCertificate(sm2Certificate, sm2Csr, ecPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(sm2Certificate, sm2Csr, rsaPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(ecCertificate, ecCsr, sm2PrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(ecCertificate, ecCsr, rsaPrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(rsaCertificate, rsaCsr, sm2PrivateKey));
        Assertions.assertFalse(CertificateUtil.checkCertificate(rsaCertificate, rsaCsr, ecPrivateKey));
    }

    private PKCS10CertificationRequest getCsr(X500Name issuer, PrivateKey privateKey) {
        PKCS10CertificationRequest sm2SelfSignedCsr = null;
        try {
            sm2SelfSignedCsr = CertificateUtil.generateCertificationRequest(issuer, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(sm2SelfSignedCsr);
        return sm2SelfSignedCsr;
    }

    private Certificate getSelfSignedCertificate(PKCS10CertificationRequest selfSignedCsr, PrivateKey privateKey) {
        Certificate selfSignedCertificate = null;
        try {
            selfSignedCertificate = CertificateUtil.generateSelfSignedCertificate(selfSignedCsr, privateKey, new Time(new Date(), Locale.CHINA), new Time(new Date(), Locale.CHINA));
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(selfSignedCertificate);
        return selfSignedCertificate;
    }

    private Certificate getCertificate(Certificate issuerCertificate, PKCS10CertificationRequest csr, PrivateKey privateKey) {
        Certificate certificate = null;
        try {
            certificate = CertificateUtil.generateCertificate(csr, issuerCertificate, privateKey, new Time(new Date(), Locale.CHINA), new Time(new Date(), Locale.CHINA));
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail();
        }
        Assertions.assertNotNull(certificate);
        return certificate;
    }
}

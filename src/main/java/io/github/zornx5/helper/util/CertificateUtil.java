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

import io.github.zornx5.helper.GlobalBouncyCastleProvider;
import io.github.zornx5.helper.constant.IHelperConstant;
import io.github.zornx5.helper.exception.KeyHelperException;
import io.github.zornx5.helper.exception.UtilException;
import io.github.zornx5.helper.key.IKeyHelper;
import io.github.zornx5.helper.key.KeyHelperManager;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * ???????????????
 *
 * @author zornx5
 */
@Slf4j
public class CertificateUtil {

    public static final Provider PROVIDER = GlobalBouncyCastleProvider.INSTANCE.getProvider();

    /**
     * ???????????????
     */
    private CertificateUtil() {
    }

    /**
     * ?????? X.509 {@link CertificateFactory}
     *
     * @return {@link CertificateFactory}
     */
    public static CertificateFactory getCertificateFactory() throws UtilException {
        return getCertificateFactory(null);
    }

    /**
     * ?????? {@link CertificateFactory}
     *
     * @param certificateType ????????????
     * @return {@link CertificateFactory}
     */
    public static CertificateFactory getCertificateFactory(String certificateType) throws UtilException {
        if (StringUtil.isBlank(certificateType)) {
            certificateType = IHelperConstant.X509_CERTIFICATE_TYPE;
        }

        CertificateFactory certificateFactory;
        try {
            certificateFactory = (null == PROVIDER)
                    ? CertificateFactory.getInstance(certificateType)
                    : CertificateFactory.getInstance(certificateType, PROVIDER);
        } catch (CertificateException e) {
            throw new UtilException(e);
        }
        return certificateFactory;
    }

    /**
     * ?????? X.509 {@link CertificateFactory}
     *
     * @return {@link CertificateFactory}
     */
    public static KeyStore getKeyStore() throws UtilException {
        return getKeyStore(null);
    }

    /**
     * ?????? {@link CertificateFactory}
     *
     * @param certificateType ????????????
     * @return {@link CertificateFactory}
     */
    public static KeyStore getKeyStore(String certificateType) throws UtilException {
        if (StringUtil.isBlank(certificateType)) {
            certificateType = IHelperConstant.PKCS12_CERTIFICATE_TYPE;
        }

        KeyStore keyStore;
        try {
            keyStore = (null == PROVIDER)
                    ? KeyStore.getInstance(certificateType)
                    : KeyStore.getInstance(certificateType, PROVIDER);
        } catch (KeyStoreException e) {
            throw new UtilException(e);
        }
        return keyStore;
    }

    /**
     * ?????? {@link X500Name}<br>
     * names ??? key ???????????? {@link BCStyle} DefaultLookUp ???????????????????????????????????????
     *
     * @param names ?????? map
     * @return {@link X500Name}
     * @throws UtilException ???????????????
     */
    public static X500Name buildX500Name(Map<String, String> names) throws UtilException {
        if (names == null || names.size() == 0) {
            throw new UtilException("names can not be empty");
        }
        try {
            X500NameBuilder builder = new X500NameBuilder();
            Iterator<Map.Entry<String, String>> itr = names.entrySet().iterator();
            BCStyle x500NameStyle = (BCStyle) BCStyle.INSTANCE;
            while (itr.hasNext()) {
                Map.Entry<String, String> entry = itr.next();
                ASN1ObjectIdentifier oid = x500NameStyle.attrNameToOID(entry.getKey());
                builder.addRDN(oid, entry.getValue());
            }
            return builder.build();
        } catch (Exception e) {
            throw new UtilException(e.getMessage(), e);
        }
    }

    public static Certificate assembleCertificate(TBSCertificate tbsCertificate, PrivateKey issuerPrivateKey) throws UtilException {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKeyToPrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);

        byte[] signData;
        try {
            signData = helper.sign(tbsCertificate.getEncoded(), issuerPrivateKey);
        } catch (IOException e) {
            log.error("???????????????????????????", e);
            throw new KeyHelperException("???????????????????????????", e);
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(tbsCertificate);
        vector.add(tbsCertificate.getSubjectPublicKeyInfo().getAlgorithm());
        vector.add(new DERBitString(signData));
        return Certificate.getInstance(new DERSequence(vector));
    }

    /**
     * ?????? PKCS#10 ????????????
     *
     * @param subject          X.500 ????????????
     * @param issuerPrivateKey ???????????????
     * @return PKCS#10 ????????????
     * @throws UtilException ???????????????
     */
    public static PKCS10CertificationRequest generateCertificationRequest(X500Name subject, PrivateKey issuerPrivateKey) throws UtilException {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKeyToPrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);
        PublicKey publicKey = helper.convertToPublicKey(issuerPrivateKey);

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        CertificationRequestInfo info = new CertificationRequestInfo(subject, subjectPublicKeyInfo, new DERSet());
        byte[] signData;
        try {
            signData = helper.sign(info.getEncoded(ASN1Encoding.DER), issuerPrivateKey);
        } catch (IOException e) {
            log.error("?????????????????????????????????", e);
            throw new KeyHelperException("?????????????????????????????????", e);
        }
        return new PKCS10CertificationRequest(new CertificationRequest(info, algorithmIdentifier, new DERBitString(signData)));
    }

    /**
     * ?????? PKCS#10 ????????????????????????
     *
     * @param csr              PKCS#10 ????????????
     * @param issuerPrivateKey ???????????????
     * @return PKCS#10 ????????????????????????
     */
    public static boolean checkCertificationRequest(PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey) {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKeyToPrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);

        byte[] signature = csr.getSignature();
        try {
            PublicKey publicKey = helper.convertToPublicKey(csr.getSubjectPublicKeyInfo());
            byte[] contentData = csr.toASN1Structure().getCertificationRequestInfo().getEncoded(ASN1Encoding.DER);
            return helper.verify(contentData, publicKey, signature);
        } catch (Exception e) {
            log.error("?????????????????????????????????", e);
        }
        return false;
    }

    /**
     * ???????????? X.509 ??????
     *
     * @param csr              PKCS#10 ????????????
     * @param issuerPrivateKey ???????????????
     * @param startDate        ????????????????????????
     * @param endDate          ????????????????????????
     * @return X.509 ??????
     * @throws UtilException ???????????????
     */
    public static Certificate generateSelfSignedCertificate(PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey, Time startDate, Time endDate) throws UtilException {
        if (!checkCertificationRequest(csr, issuerPrivateKey)) {
            throw new UtilException("????????????????????????");
        }
        X500Name subject = csr.getSubject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();

        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
            //??????????????????
            AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
            //?????????????????????
            SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        } catch (IOException e) {
            log.error("??????????????????", e);
            throw new KeyHelperException("??????????????????", e);
        }

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE));
        // ????????????????????????????????????
        tbsGen.setIssuer(subject);
        tbsGen.setSubject(subject);
        tbsGen.setStartDate(startDate);
        tbsGen.setEndDate(endDate);
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        tbsGen.setExtensions(extensionsGenerator.generate());
        // ????????????????????????????????????????????????????????????
        tbsGen.setSignature(subjectPublicKeyInfo.getAlgorithm());
        TBSCertificate tbsCertificate = tbsGen.generateTBSCertificate();
        return assembleCertificate(tbsCertificate, issuerPrivateKey);
    }

    /**
     * ?????? X.509 ??????
     *
     * @param csr               PKCS#10 ????????????
     * @param issuerCertificate ???????????????
     * @param issuerPrivateKey  ???????????????
     * @param startDate         ????????????????????????
     * @param endDate           ????????????????????????
     * @return X.509 ??????
     * @throws UtilException ???????????????
     */
    public static Certificate generateCertificate(PKCS10CertificationRequest csr, Certificate issuerCertificate, PrivateKey issuerPrivateKey, Time startDate, Time endDate) throws UtilException {
        if (!checkCertificationRequest(csr, issuerPrivateKey)) {
            throw new UtilException("????????????????????????");
        }

        X509CertificateHolder issuer = new X509CertificateHolder(issuerCertificate);

        X500Name subject = csr.getSubject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();

        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            // ??????????????????
            AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(issuer);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
            //?????????????????????
            SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        } catch (IOException e) {
            log.error("??????????????????", e);
            throw new KeyHelperException("??????????????????", e);
        }

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE));
        tbsGen.setIssuer(issuer.getSubject());
        tbsGen.setSubject(subject);
        tbsGen.setStartDate(startDate);
        tbsGen.setEndDate(endDate);
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        tbsGen.setExtensions(extensionsGenerator.generate());
        // ????????????????????????????????????????????????????????????
        tbsGen.setSignature(issuer.getSubjectPublicKeyInfo().getAlgorithm());
        TBSCertificate tbsCertificate = tbsGen.generateTBSCertificate();
        return assembleCertificate(tbsCertificate, issuerPrivateKey);
    }

    /**
     * ?????? X.509 ??????????????????
     *
     * @param certificate      X.509 ??????
     * @param issuerPrivateKey ???????????????
     * @return ?????? X.509 ??????????????????
     */
    public static boolean checkCertificate(Certificate certificate, PrivateKey issuerPrivateKey) {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKeyToPrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);

        byte[] signature = certificate.getSignature().getBytes();
        try {
            PublicKey publicKey = helper.convertToPublicKey(certificate.getSubjectPublicKeyInfo());
            byte[] contentData = certificate.getTBSCertificate().getEncoded();
            return helper.verify(contentData, publicKey, signature);
        } catch (Exception e) {
            log.error("??????", e);
        }
        return false;
    }

    /**
     * ?????? X.509 ??????????????????
     *
     * @param certificate      X.509 ??????
     * @param csr              PKCS#10 ????????????
     * @param issuerPrivateKey ???????????????
     * @return ?????? X.509 ??????????????????
     */
    public static boolean checkCertificate(Certificate certificate, PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey) {
        boolean checkCertificationRequest = checkCertificationRequest(csr, issuerPrivateKey);
        boolean checkCertificate = checkCertificate(certificate, issuerPrivateKey);
        return checkCertificationRequest && checkCertificate;
    }

    public static String convertPKCS10CertificationRequest2Base64String(PKCS10CertificationRequest csr) {
        log.info("????????????????????? Base64 ??????????????????");
        if (csr == null) {
            log.error("????????????????????????");
            throw new UtilException("????????????????????????");
        }
        String base64Csr;
        try {
            base64Csr = new String(Base64.getEncoder().encode(csr.getEncoded()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("?????????????????????????????????", e);
            throw new UtilException("?????????????????????????????????", e);
        }
        log.info("????????????????????? Base64 ????????????????????????");
        return base64Csr;
    }

    public static String convertCertificate2Base64String(Certificate certificate) {
        log.info("??????????????? Base64 ????????????");
        if (certificate == null) {
            log.error("??????????????????");
            throw new UtilException("??????????????????");
        }
        String base64Certificate;
        try {
            base64Certificate = new String(Base64.getEncoder().encode(certificate.getEncoded()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("???????????????????????????", e);
            throw new UtilException("???????????????????????????", e);
        }
        log.info("??????????????? Base64 ??????????????????");
        return base64Certificate;
    }

    public static String convertCertificate2Base64String(X509Certificate certificate) {
        log.info("??????????????? Base64 ????????????");
        if (certificate == null) {
            log.error("??????????????????");
            throw new UtilException("??????????????????");
        }
        String base64Certificate;
        try {
            base64Certificate = new String(Base64.getEncoder().encode(certificate.getEncoded()), StandardCharsets.UTF_8);
        } catch (CertificateEncodingException e) {
            log.error("???????????????????????????", e);
            throw new UtilException("???????????????????????????", e);
        }
        log.info("??????????????? Base64 ??????????????????");
        return base64Certificate;
    }

    public static X509Certificate convertPem2Certificate(String pemCertificate) {
        return convertByte2Certificate(PemUtil.readPemOrBase64Content(pemCertificate));
    }

    public static X509Certificate convertBase64String2Certificate(String base64Certificate) {
        return convertByte2Certificate(Base64.getDecoder().decode(base64Certificate.getBytes(StandardCharsets.UTF_8)));
    }

    public static X509Certificate convertByte2Certificate(byte[] byteCertificate) {
        log.info("??????????????????????????????");
        if (byteCertificate == null || byteCertificate.length < 1) {
            log.error("???????????????????????????");
            throw new UtilException("???????????????????????????");
        }
        CertificateFactory certificateFactory = getCertificateFactory();
        try {
            X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(byteCertificate));
            log.info("????????????????????????????????????");
            return x509Certificate;
        } catch (CertificateException e) {
            log.error("???????????????????????????", e);
            throw new UtilException("???????????????????????????", e);
        }
    }

    /**
     * ????????????
     *
     * @param issuerPubKey    ????????????CA??????????????????????????????
     * @param x509Certificate ??????????????????
     * @return ????????????
     */
    public static boolean verifyCertificate(PublicKey issuerPubKey, X509Certificate x509Certificate) {
        try {
            x509Certificate.verify(issuerPubKey, GlobalBouncyCastleProvider.INSTANCE.getProvider());
        } catch (Exception ex) {
            return false;
        }
        return true;
    }

    public static X509Certificate getX509Certificate(String certificateFilePath) throws IOException, CertificateException {
        try (InputStream inputStream = new FileInputStream(certificateFilePath)) {
            return getX509Certificate(inputStream);
        }
    }

    public static X509Certificate getX509Certificate(byte[] certificate) throws CertificateException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certificate);
        return getX509Certificate(byteArrayInputStream);
    }

    public static X509Certificate getX509Certificate(InputStream certificate) throws CertificateException {
        CertificateFactory certificateFactory = getCertificateFactory();
        return (X509Certificate) certificateFactory.generateCertificate(certificate);
    }

    public static CertPath getCertificateChain(String certificateChainPath) throws IOException, CertificateException {
        try (InputStream inputStream = new FileInputStream(certificateChainPath)) {
            return getCertificateChain(inputStream);
        }
    }

    public static CertPath getCertificateChain(byte[] certificateChainBytes) throws CertificateException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certificateChainBytes);
        return getCertificateChain(byteArrayInputStream);
    }

    public static byte[] getCertificateChainBytes(CertPath certificateChain) throws CertificateEncodingException {
        return certificateChain.getEncoded("PKCS7");
    }

    public static CertPath getCertificateChain(InputStream is) throws CertificateException {
        CertificateFactory certificateFactory = getCertificateFactory();
        return certificateFactory.generateCertPath(is, "PKCS7");
    }

    public static CertPath getCertificateChain(List<X509Certificate> certs) throws CertificateException {
        CertificateFactory certificateFactory = getCertificateFactory();
        return certificateFactory.generateCertPath(certs);
    }

    public static X509Certificate getX509CertificateFromPfx(byte[] pfxDER, String passwd) throws Exception {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                .setProvider(GlobalBouncyCastleProvider.INSTANCE.getProvider()).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                X509CertificateHolder certHoler = (X509CertificateHolder) bags[0].getBagValue();
                return getX509Certificate(certHoler.getEncoded());
            }
        }

        throw new Exception("Not found X509Certificate in this pfx");
    }

    public static PublicKey getPublicKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        return getX509CertificateFromPfx(pfxDER, passwd).getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                .setProvider(GlobalBouncyCastleProvider.INSTANCE.getProvider()).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (!infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo) bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
                return KeyHelperManager.getByName("Sm2").convertToPrivateKey(info);
            }
        }

        throw new Exception("Not found Private Key in this pfx");
    }
}

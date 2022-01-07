package io.github.zornx5.helper.certificate.impl;

import io.github.zornx5.helper.certificate.ICertificateHelper;
import io.github.zornx5.helper.certificate.exception.CertificateHelperException;
import io.github.zornx5.helper.key.IKeyHelper;
import io.github.zornx5.helper.key.KeyHelperManager;
import io.github.zornx5.helper.key.exception.KeyHelperException;
import io.github.zornx5.helper.util.KeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

/**
 * 证书帮助类
 *
 * @author zornx5
 */
@Slf4j
public class CertificateHelper implements ICertificateHelper {

    public Certificate assembleCert(TBSCertificate tbsCertificate, PrivateKey issuerPrivateKey) {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKey2PrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);

        byte[] signData;
        try {
            signData = helper.sign(tbsCertificate.getEncoded(), issuerPrivateKey);
        } catch (IOException e) {
            log.error("获取证书字节码异常", e);
            throw new KeyHelperException("获取证书字节码异常", e);
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(tbsCertificate);
        vector.add(tbsCertificate.getSubjectPublicKeyInfo().getAlgorithm());
        vector.add(new DERBitString(signData));
        return Certificate.getInstance(new DERSequence(vector));
    }

    @Override
    public PKCS10CertificationRequest generateCertificationRequest(X500Name subject, PrivateKey issuerPrivateKey) {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKey2PrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);
        PublicKey publicKey = helper.convertPrivateKey2PublicKey(issuerPrivateKey);

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        CertificationRequestInfo info = new CertificationRequestInfo(subject, subjectPublicKeyInfo, new DERSet());
        byte[] signData;
        try {
            signData = helper.sign(info.getEncoded(ASN1Encoding.DER), issuerPrivateKey);
        } catch (IOException e) {
            log.error("获取证书请求字节码异常", e);
            throw new KeyHelperException("获取证书请求字节码异常", e);
        }
        return new PKCS10CertificationRequest(new CertificationRequest(info, algorithmIdentifier, new DERBitString(signData)));
    }

    @Override
    public boolean checkCertificationRequest(PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey) {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKey2PrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);

        byte[] signature = csr.getSignature();
        try {
            PublicKey publicKey = helper.convertSubjectPublicKeyInfo2PublicKey(csr.getSubjectPublicKeyInfo());
            byte[] contentData = csr.toASN1Structure().getCertificationRequestInfo().getEncoded(ASN1Encoding.DER);
            return helper.verify(contentData, signature, publicKey);
        } catch (Exception e) {
            log.error("获取证书请求字节码异常", e);
        }
        return false;
    }

    @Override
    public Certificate generateSelfSignedCertificate(PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey, Time startDate, Time endDate) {
        if (!checkCertificationRequest(csr, issuerPrivateKey)) {
            throw new CertificateHelperException("证书请求验证失败");
        }
        X500Name subject = csr.getSubject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();

        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
            //授权密钥标识
            AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
            //使用者密钥标识
            SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        } catch (IOException e) {
            log.error("扩展生成异常", e);
            throw new KeyHelperException("扩展生成异常", e);
        }

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE));
        // 自签证书颁发者等于使用者
        tbsGen.setIssuer(subject);
        tbsGen.setSubject(subject);
        tbsGen.setStartDate(startDate);
        tbsGen.setEndDate(endDate);
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        tbsGen.setExtensions(extensionsGenerator.generate());
        // 签名算法标识等于颁发者证书的密钥算法标识
        tbsGen.setSignature(subjectPublicKeyInfo.getAlgorithm());
        TBSCertificate tbsCertificate = tbsGen.generateTBSCertificate();
        return assembleCert(tbsCertificate, issuerPrivateKey);
    }

    @Override
    public Certificate generateCertificate(PKCS10CertificationRequest csr, Certificate issuerCertificate, PrivateKey issuerPrivateKey, Time startDate, Time endDate) {
        if (!checkCertificationRequest(csr, issuerPrivateKey)) {
            throw new CertificateHelperException("证书请求验证失败");
        }

        X509CertificateHolder issuer = new X509CertificateHolder(issuerCertificate);

        X500Name subject = csr.getSubject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();

        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            // 授权密钥标识
            AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(issuer);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
            //使用者密钥标识
            SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        } catch (IOException e) {
            log.error("扩展生成异常", e);
            throw new KeyHelperException("扩展生成异常", e);
        }

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE));
        tbsGen.setIssuer(issuer.getSubject());
        tbsGen.setSubject(subject);
        tbsGen.setStartDate(startDate);
        tbsGen.setEndDate(endDate);
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        tbsGen.setExtensions(extensionsGenerator.generate());
        // 签名算法标识等于颁发者证书的密钥算法标识
        tbsGen.setSignature(issuer.getSubjectPublicKeyInfo().getAlgorithm());
        TBSCertificate tbsCertificate = tbsGen.generateTBSCertificate();
        return assembleCert(tbsCertificate, issuerPrivateKey);
    }

    @Override
    public boolean checkCertificate(Certificate certificate, PrivateKey issuerPrivateKey) {
        PrivateKeyInfo privateKeyInfo = KeyUtil.convertPrivateKey2PrivateKeyInfo(issuerPrivateKey);
        AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        IKeyHelper helper = KeyHelperManager.getByAlgorithm(algorithmIdentifier);

        byte[] signature = certificate.getSignature().getBytes();
        try {
            PublicKey publicKey = helper.convertSubjectPublicKeyInfo2PublicKey(certificate.getSubjectPublicKeyInfo());
            byte[] contentData = certificate.getTBSCertificate().getEncoded();
            return helper.verify(contentData, signature, publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean checkCertificate(Certificate certificate, PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey) {
        boolean checkCertificationRequest = checkCertificationRequest(csr, issuerPrivateKey);
        boolean checkCertificate = checkCertificate(certificate, issuerPrivateKey);
        return checkCertificationRequest && checkCertificate;
    }
}

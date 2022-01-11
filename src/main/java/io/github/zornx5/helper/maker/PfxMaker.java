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

import io.github.zornx5.helper.exception.MakerException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * PFX 构建器
 *
 * @author zornx5
 */
@Slf4j
public class PfxMaker {

    String leafCertificateName;
    String midCaCertificateName;
    String rootCaCertificateName;

    public PfxMaker() {
        leafCertificateName = "Primary Certificate";
        midCaCertificateName = "Intermediate Certificate";
        rootCaCertificateName = "User Key";
    }

    /**
     * 制作 PFX
     *
     * @param privateKey 用户私钥
     * @param publicKey  用户公钥
     * @param chain      X509 证书数组，切记这里固定了必须是 3 个元素的数组，且第一个必须是叶子证书、第二个为中级 CA 证书、第三个为根 CA 证书
     * @param password   口令
     * @return PKCS12PfxPdu
     * @throws MakerException 没有提供者异常
     */
    public PKCS12PfxPdu makePfx(PrivateKey privateKey, PublicKey publicKey, X509Certificate[] chain, String password) throws MakerException {
        JcaX509ExtensionUtils extUtils;
        try {
            extUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            log.error("算法不支持异常", e);
            throw new MakerException("算法不支持异常", e);
        }

        PKCS12SafeBagBuilder taCertBagBuilder;
        PKCS12SafeBagBuilder caCertBagBuilder;
        try {
            taCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[2]);
            caCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[1]);
        } catch (IOException e) {
            log.error("读取异常", e);
            throw new MakerException("读取异常", e);
        }

        taCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString(leafCertificateName));
        caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString(midCaCertificateName));

        PKCS12SafeBag[] certs = new PKCS12SafeBag[3];
        certs[1] = caCertBagBuilder.build();
        certs[2] = taCertBagBuilder.build();

        return makeEePkcs12PfxPdu(privateKey, publicKey, chain[0], password, extUtils, certs);
    }

    /**
     * 制作 PFX
     *
     * @param privateKey  用户私钥
     * @param publicKey   用户公钥
     * @param certificate X509证书
     * @param password    口令
     * @return PKCS12PfxPdu
     * @throws MakerException 制作器异常
     */
    public PKCS12PfxPdu makePfx(PrivateKey privateKey, PublicKey publicKey, X509Certificate certificate, String password) throws MakerException {
        JcaX509ExtensionUtils extUtils;
        try {
            extUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            log.error("算法不支持异常", e);
            throw new MakerException("算法不支持异常", e);
        }

        PKCS12SafeBag[] certs = new PKCS12SafeBag[1];

        return makeEePkcs12PfxPdu(privateKey, publicKey, certificate, password, extUtils, certs);
    }

    private PKCS12PfxPdu makeEePkcs12PfxPdu(PrivateKey privateKey, PublicKey publicKey, X509Certificate certificate, String password, JcaX509ExtensionUtils extUtils, PKCS12SafeBag[] certs) {
        PKCS12SafeBagBuilder eeCertBagBuilder;
        try {
            eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(certificate);
        } catch (IOException e) {
            log.error("读取异常", e);
            throw new MakerException("读取异常", e);
        }

        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString(rootCaCertificateName));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(publicKey));

        char[] passwdChars = password.toCharArray();
        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privateKey,
                new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                        new CBCBlockCipher(new DESedeEngine())).build(passwdChars));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString(rootCaCertificateName));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(publicKey));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        certs[0] = eeCertBagBuilder.build();
        try {
            pfxPduBuilder.addEncryptedData(
                    new BcPKCS12PBEOutputEncryptorBuilder(
                            PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                            new CBCBlockCipher(new RC2Engine())).build(passwdChars),
                    certs);
            pfxPduBuilder.addData(keyBagBuilder.build());
        } catch (IOException e) {
            log.error("读取异常", e);
            throw new MakerException("读取异常", e);
        }
        try {
            return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwdChars);
        } catch (PKCSException e) {
            log.error("PKCS 格式异常", e);
            throw new MakerException("PKCS 格式异常", e);
        }
    }
}

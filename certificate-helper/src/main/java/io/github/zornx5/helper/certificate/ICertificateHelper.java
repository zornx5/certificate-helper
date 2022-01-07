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

package io.github.zornx5.helper.certificate;


import io.github.zornx5.helper.certificate.exception.CertificateHelperException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;

/**
 * 证书帮助类
 *
 * @author zornx5
 */
public interface ICertificateHelper {

    /**
     * 生成 PKCS#10 认证请求
     *
     * @param subject          X.500 名称对象
     * @param issuerPrivateKey 签发者私钥
     * @return PKCS#10 认证请求
     * @throws CertificateHelperException 证书帮助异常
     */
    PKCS10CertificationRequest generateCertificationRequest(X500Name subject, PrivateKey issuerPrivateKey) throws CertificateHelperException;

    /**
     * 检查 PKCS#10 认证请求是否匹配
     *
     * @param csr              PKCS#10 认证请求
     * @param issuerPrivateKey 签发者私钥
     * @return PKCS#10 认证请求是否匹配
     */
    boolean checkCertificationRequest(PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey);

    /**
     * 生成自签 X.509 证书
     *
     * @param csr              PKCS#10 认证请求
     * @param issuerPrivateKey 签发者私钥
     * @param startDate        证书有效开始时间
     * @param endDate          证书有效结束时间
     * @return X.509 证书
     * @throws CertificateHelperException 证书帮助异常
     */
    Certificate generateSelfSignedCertificate(PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey, Time startDate, Time endDate) throws CertificateHelperException;

    /**
     * 生成 X.509 证书
     *
     * @param csr               PKCS#10 认证请求
     * @param issuerCertificate 签发者证书
     * @param issuerPrivateKey  签发者私钥
     * @param startDate         证书有效开始时间
     * @param endDate           证书有效结束时间
     * @return X.509 证书
     * @throws CertificateHelperException 证书帮助异常
     */
    Certificate generateCertificate(PKCS10CertificationRequest csr, Certificate issuerCertificate, PrivateKey issuerPrivateKey, Time startDate, Time endDate) throws CertificateHelperException;

    /**
     * 检查 X.509 证书是否匹配
     *
     * @param certificate      X.509 证书
     * @param issuerPrivateKey 签发者私钥
     * @return 检查 X.509 证书是否匹配
     */
    boolean checkCertificate(Certificate certificate, PrivateKey issuerPrivateKey);

    /**
     * 检查 X.509 证书是否匹配
     *
     * @param certificate      X.509 证书
     * @param csr              PKCS#10 认证请求
     * @param issuerPrivateKey 签发者私钥
     * @return 检查 X.509 证书是否匹配
     */
    boolean checkCertificate(Certificate certificate, PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey);
}

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

import io.github.zornx5.helper.exception.CertificateHelperException;
import io.github.zornx5.helper.exception.KeyHelperException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 抽象密钥帮助类接口
 *
 * @author zornx5
 */
public interface IKeyHelper {

    /**
     * 生成密钥对 <br>
     * 私钥 PKCS#8 格式 <br>
     * 公钥 X.509 格式
     *
     * @return 密钥对 {@link KeyPair}
     * @throws CertificateHelperException 证书帮助异常
     */
    KeyPair generateKeyPair() throws CertificateHelperException;

    /**
     * 生成密钥对 <br>
     * 私钥 PKCS#8 格式 <br>
     * 公钥 X.509 格式
     *
     * @param keySize 这是一个特定于算法的度量，例如模数长度，以位数指定。
     * @return 密钥对 {@link KeyPair}
     * @throws CertificateHelperException 证书帮助异常
     */
    KeyPair generateKeyPair(int keySize) throws CertificateHelperException;

    /**
     * 检查密钥对是否匹配
     *
     * @param base64OrPemPrivateKey base64 编码的私钥字符串或 PEM 私钥字符串
     * @param base64OrPemPublicKey  base64 编码的公钥字符串或 PEM 公钥字符串
     * @return 密钥对是否匹配
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean checkKeyPair(String base64OrPemPrivateKey, String base64OrPemPublicKey) throws CertificateHelperException;

    /**
     * 检查密钥对是否匹配
     *
     * @param privateKey           私钥
     * @param subjectPublicKeyInfo 公钥信息
     * @return 密钥对是否匹配
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean checkKeyPair(PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo) throws CertificateHelperException;

    /**
     * 检查密钥对是否匹配
     *
     * @param privateKeyInfo 私钥公钥信息
     * @param publicKey      公钥
     * @return 密钥对是否匹配
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean checkKeyPair(PrivateKeyInfo privateKeyInfo, PublicKey publicKey) throws CertificateHelperException;

    /**
     * 检查密钥对是否匹配
     *
     * @param privateKeyInfo       私钥公钥信息
     * @param subjectPublicKeyInfo 公钥信息
     * @return 密钥对是否匹配
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean checkKeyPair(PrivateKeyInfo privateKeyInfo, SubjectPublicKeyInfo subjectPublicKeyInfo) throws CertificateHelperException;

    /**
     * 检查密钥对是否匹配
     *
     * @param privateKey 私钥
     * @param publicKey  公钥
     * @return 密钥对是否匹配
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean checkKeyPair(PrivateKey privateKey, PublicKey publicKey) throws CertificateHelperException;

    /**
     * 检查密钥对是否匹配
     *
     * @param privateKey 私钥数据
     * @param publicKey  公钥数据
     * @return 密钥对是否匹配
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean checkKeyPair(byte[] privateKey, byte[] publicKey) throws CertificateHelperException;

    /**
     * base64 编码的私钥字串转换成 {@link java.security.PrivateKey} 对象
     *
     * @param base64OrPemPrivateKey base64 编码的私钥字符串或 PEM 私钥字符串
     * @return PublicKey
     * @throws CertificateHelperException 证书帮助异常
     * @see java.security.PrivateKey
     */
    PrivateKey convertString2PrivateKey(String base64OrPemPrivateKey) throws CertificateHelperException;

    /**
     * 私钥 {@link PrivateKey} 转换成私钥信息 {@link PrivateKeyInfo}
     *
     * @param privateKey 私钥
     * @return 私钥
     * @throws CertificateHelperException 证书帮助异常
     */
    PrivateKeyInfo convertPrivateKey2PrivateKeyInfo(PrivateKey privateKey) throws CertificateHelperException;

    /**
     * 私钥信息 {@link PrivateKeyInfo} 转换成私钥 {@link PrivateKey}
     *
     * @param privateKeyInfo 私钥信息
     * @return 私钥
     * @throws CertificateHelperException 证书帮助异常
     */
    PrivateKey convertPrivateKeyInfo2PrivateKey(PrivateKeyInfo privateKeyInfo) throws CertificateHelperException;

    /**
     * 私钥数据转换成 {@link java.security.PrivateKey} 对象
     *
     * @param privateKey 私钥数据
     * @return PublicKey
     * @throws CertificateHelperException 证书帮助异常
     * @see java.security.PrivateKey
     */
    PrivateKey convertData2PrivateKey(byte[] privateKey) throws CertificateHelperException;

    /**
     * base64 编码的公钥字串转换成 {@link java.security.PublicKey} 对象
     *
     * @param base64OrPemPublicKey base64 编码的公钥字符串或 PEM 公钥字符串
     * @return PublicKey
     * @throws CertificateHelperException 证书帮助异常
     */
    PublicKey convertBase64String2PublicKey(String base64OrPemPublicKey) throws CertificateHelperException;

    /**
     * {@link SubjectPublicKeyInfo} 转换成 {@link PublicKey}
     *
     * @param subjectPublicKeyInfo 公钥信息
     * @return 公钥
     * @throws CertificateHelperException 证书帮助异常
     */
    PublicKey convertSubjectPublicKeyInfo2PublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws CertificateHelperException;

    /**
     * 公钥数据转换成 {@link java.security.PublicKey} 对象
     *
     * @param publicKey 公钥数据
     * @return PublicKey
     * @throws CertificateHelperException 证书帮助异常
     */
    PublicKey convertData2PublicKey(byte[] publicKey) throws CertificateHelperException;

    /**
     * 从 {@link PrivateKey} 中解析 {@link PublicKey}
     *
     * @param privateKey 私钥
     * @return 公钥
     * @throws CertificateHelperException 证书帮助异常
     */
    PublicKey convertPrivateKey2PublicKey(PrivateKey privateKey) throws CertificateHelperException;

    /**
     * 从 {@link PrivateKey} 数据中解析 {@link PublicKey}
     *
     * @param privateKey 私钥数据
     * @return 公钥
     * @throws CertificateHelperException 证书帮助异常
     */
    PublicKey convertPrivateKey2PublicKey(byte[] privateKey) throws CertificateHelperException;

    /**
     * 转换旧 PKCS#1 （Openssl）私钥成 PKCS#8 （Java）格式
     *
     * @param pkcs1PrivateKey PKCS#1 （Java）私钥
     * @return PKCS#8 编码私钥
     * @throws CertificateHelperException 证书帮助异常
     */
    PrivateKey convertPkcs1ToPkcs8(byte[] pkcs1PrivateKey) throws CertificateHelperException;

    /**
     * 私钥转换成 PEM 字串
     *
     * @param privateKey 私钥
     * @return PEM 字串
     * @throws KeyHelperException 密钥帮助异常
     */
    String convertToPkcs1Pem(PrivateKey privateKey) throws KeyHelperException;

    /**
     * 私钥转换成 PKCS1 Base64 字串
     *
     * @param privateKey 私钥
     * @return PEM 字串
     * @throws KeyHelperException 密钥帮助异常
     */
    String convertToBase64Pkcs1String(PrivateKey privateKey) throws KeyHelperException;

    /**
     * 计算指定内容的签名
     *
     * @param plainText             待签名的原文
     * @param charset               待签名的原文的字符集编码
     * @param base64OrPemPrivateKey base64 编码的私钥字符串或 PEM 私钥字符串
     * @return 签名字符串
     * @throws CertificateHelperException 证书帮助异常
     */
    String sign(String plainText, String charset, String base64OrPemPrivateKey) throws CertificateHelperException;

    /**
     * 计算指定内容的签名
     *
     * @param plainText  待签名的数据
     * @param privateKey 私钥
     * @return 签名字符串
     * @throws CertificateHelperException 证书帮助异常
     */
    byte[] sign(byte[] plainText, PrivateKey privateKey) throws CertificateHelperException;

    /**
     * 计算指定内容的签名
     *
     * @param plainText  待签名的数据
     * @param privateKey 私钥数据
     * @return 签名字符串
     * @throws CertificateHelperException 证书帮助异常
     */
    byte[] sign(byte[] plainText, byte[] privateKey) throws CertificateHelperException;

    /**
     * 验证指定内容的签名是否正确
     *
     * @param plainText            原文
     * @param charset              原文的字符集编码
     * @param base64OrPemPublicKey base64 编码的公钥字符串或 PEM 公钥字符串
     * @param base64Signature      Base64 编码的签名字符串
     * @return true：验证通过；false：验证不通过
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean verify(String plainText, String charset, String base64OrPemPublicKey, String base64Signature) throws CertificateHelperException;

    /**
     * 验证指定内容的签名是否正确
     *
     * @param plainText 原文数据
     * @param publicKey 公钥字符串
     * @param signature 签名数据
     * @return true：验证通过；false：验证不通过
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean verify(byte[] plainText, PublicKey publicKey, byte[] signature) throws CertificateHelperException;

    /**
     * 验证指定内容的签名是否正确
     *
     * @param plainText 原文数据
     * @param publicKey 公钥字符串
     * @param signature 签名数据
     * @return true：验证通过；false：验证不通过
     * @throws CertificateHelperException 证书帮助异常
     */
    boolean verify(byte[] plainText, byte[] publicKey, byte[] signature) throws CertificateHelperException;

    /**
     * 对明文进行非对称加密
     *
     * @param plainText            明文字符串
     * @param charset              明文的字符集编码
     * @param base64OrPemPublicKey base64 编码的公钥字符串或 PEM 公钥字符串
     * @return 密文的 Base64 编码字符串
     * @throws CertificateHelperException 证书帮助异常
     */
    String encrypt(String plainText, String charset, String base64OrPemPublicKey) throws CertificateHelperException;

    /**
     * 对明文进行非对称加密
     *
     * @param plainText 明文字符串
     * @param publicKey 公钥
     * @return 密文的 Base64 编码字符串
     * @throws CertificateHelperException 证书帮助异常
     */
    byte[] encrypt(byte[] plainText, PublicKey publicKey) throws CertificateHelperException;

    /**
     * 对明文进行非对称加密
     *
     * @param plainText 明文字符串
     * @param publicKey 公钥数据
     * @return 密文的 Base64 编码字符串
     * @throws CertificateHelperException 证书帮助异常
     */
    byte[] encrypt(byte[] plainText, byte[] publicKey) throws CertificateHelperException;

    /**
     * 对 Base64 编码密文进行非对称解密
     *
     * @param base64CipherText      Base64 编码的密文字符串
     * @param charset               明文的字符集编码
     * @param base64OrPemPrivateKey base64 编码的私钥字符串或 PEM 私钥字符串
     * @return 明文
     * @throws CertificateHelperException 证书帮助异常
     */
    String decrypt(String base64CipherText, String charset, String base64OrPemPrivateKey) throws CertificateHelperException;

    /**
     * 对密文进行非对称解密
     *
     * @param cipherText 密文数据
     * @param privateKey 私钥
     * @return 明文
     * @throws CertificateHelperException 证书帮助异常
     */
    byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws CertificateHelperException;

    /**
     * 对密文进行非对称解密
     *
     * @param cipherText 密文数据
     * @param privateKey 私钥数据
     * @return 明文
     * @throws CertificateHelperException 证书帮助异常
     */
    byte[] decrypt(byte[] cipherText, byte[] privateKey) throws CertificateHelperException;

}

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

import io.github.zornx5.helper.key.exception.KeyHelperException;
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
     * @return 密钥对
     * @throws KeyHelperException 密钥帮助异常
     */
    KeyPair generateKeyPair() throws KeyHelperException;

    /**
     * 生成密钥对 <br>
     * 私钥 PKCS#8 格式 <br>
     * 公钥 X.509 格式
     *
     * @param keySize 这是一个特定于算法的度量，例如模数长度，以位数指定。
     * @return 密钥对
     * @throws KeyHelperException 密钥帮助异常
     */
    KeyPair generateKeyPair(int keySize) throws KeyHelperException;

    /**
     * 检查密钥对是否匹配
     *
     * @param privateKey 私钥
     * @param publicKey  公钥
     * @return 密钥对是否匹配
     * @throws KeyHelperException 密钥帮助异常
     */
    boolean checkKeyPair(PrivateKey privateKey, PublicKey publicKey) throws KeyHelperException;

    /**
     * 私钥信息转换成 {@link PrivateKey}
     *
     * @param privateKeyInfo 私钥信息
     * @return 私钥
     * @throws KeyHelperException 密钥帮助异常
     */
    PrivateKey convertPrivateKeyInfo2PrivateKey(PrivateKeyInfo privateKeyInfo) throws KeyHelperException;

    /**
     * 从 {@link PrivateKey} 中解析 {@link PublicKey}
     *
     * @param privateKey 私钥
     * @return 公钥
     * @throws KeyHelperException 密钥帮助异常
     */
    PublicKey convertPrivateKey2PublicKey(PrivateKey privateKey) throws KeyHelperException;

    /**
     * {@link SubjectPublicKeyInfo} 转换成 {@link PublicKey}
     *
     * @param subjectPublicKeyInfo 公钥信息
     * @return 公钥
     * @throws KeyHelperException 密钥帮助异常
     */
    PublicKey convertSubjectPublicKeyInfo2PublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws KeyHelperException;

    /**
     * base64 编码的私钥字串转换成 {@link java.security.PrivateKey} 对象
     *
     * @param base64PrivateKey base64 编码的私钥字串
     * @return PublicKey
     * @throws KeyHelperException 密钥帮助异常
     * @see java.security.PrivateKey
     */
    PrivateKey convertBase64String2PrivateKey(String base64PrivateKey) throws KeyHelperException;

    /**
     * base64 编码的公钥字串转换成 {@link java.security.PublicKey} 对象
     *
     * @param base64PublicKey base64 编码的公钥字串
     * @return PublicKey
     * @throws KeyHelperException 密钥帮助异常
     */
    PublicKey convertBase64String2PublicKey(String base64PublicKey) throws KeyHelperException;

    /**
     * 转换旧 PKCS#1 （Openssl）私钥成 PKCS#8 （Java）格式
     *
     * @param pkcs1PrivateKey PKCS#1 （Java）私钥
     * @return PKCS#8 编码私钥
     * @throws KeyHelperException 密钥帮助异常
     */
    PrivateKey convertPkcs1ToPkcs8(byte[] pkcs1PrivateKey) throws KeyHelperException;

    /**
     * 计算指定内容的签名
     *
     * @param content    待签名的原文
     * @param charset    待签名的原文的字符集编码
     * @param privateKey 私钥字符串
     * @return 签名字符串
     * @throws KeyHelperException 密钥帮助异常
     */
    String sign(String content, String charset, String privateKey) throws KeyHelperException;

    /**
     * 计算指定内容的签名
     *
     * @param contentData 待签名的数组
     * @param privateKey  私钥
     * @return 签名字符串
     * @throws KeyHelperException 密钥帮助异常
     */
    byte[] sign(byte[] contentData, PrivateKey privateKey) throws KeyHelperException;

    /**
     * 验证指定内容的签名是否正确
     *
     * @param content   待校验的原文
     * @param charset   待校验的原文的字符集编码
     * @param publicKey 公钥字符串
     * @param sign      签名字符串
     * @return true：验证通过；false：验证不通过
     * @throws KeyHelperException 密钥帮助异常
     */
    boolean verify(String content, String charset, String publicKey, String sign) throws KeyHelperException;

    /**
     * 验证指定内容的签名是否正确
     *
     * @param contentData 待校验的数据
     * @param signData    签名数据
     * @param publicKey   签名字符串
     * @return true：验证通过；false：验证不通过
     * @throws KeyHelperException 密钥帮助异常
     */
    boolean verify(byte[] contentData, byte[] signData, PublicKey publicKey) throws KeyHelperException;


    /**
     * 对明文进行非对称加密
     *
     * @param plainText 明文字符串
     * @param charset   明文的字符集编码
     * @param publicKey 公钥字符串
     * @return 密文的 Base64 编码字符串
     * @throws KeyHelperException 密钥帮助异常
     */
    String encrypt(String plainText, String charset, String publicKey) throws KeyHelperException;

    /**
     * 对密文进行非对称解密
     *
     * @param cipherTextBase64 密文 Base64 编码字符串
     * @param charset          明文的字符集编码
     * @param privateKey       私钥字符串
     * @return 明文
     * @throws KeyHelperException 密钥帮助异常
     */
    String decrypt(String cipherTextBase64, String charset, String privateKey) throws KeyHelperException;
}

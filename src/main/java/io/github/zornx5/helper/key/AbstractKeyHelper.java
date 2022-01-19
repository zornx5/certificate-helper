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

import io.github.zornx5.helper.constant.IHelperConstant;
import io.github.zornx5.helper.exception.CertificateHelperException;
import io.github.zornx5.helper.exception.KeyHelperException;
import io.github.zornx5.helper.exception.UtilException;
import io.github.zornx5.helper.util.Base64Util;
import io.github.zornx5.helper.util.KeyUtil;
import io.github.zornx5.helper.util.PemUtil;
import io.github.zornx5.helper.util.StringUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Encodable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * 抽象密钥帮助类
 *
 * @author zornx5
 */
@Slf4j
public abstract class AbstractKeyHelper implements IKeyHelper {

    protected KeyPairGenerator keyPairGenerator;

    protected KeyFactory keyFactory;

    protected Signature signature;

    protected Cipher cipher;

    protected String algorithm;
    protected String signAlgorithm;
    protected String cipherAlgorithm;

    protected int keySize;

    protected AbstractKeyHelper(String algorithm, String signAlgorithm, String cipherAlgorithm, int keySize) {
        this.algorithm = algorithm;
        this.signAlgorithm = signAlgorithm;
        this.cipherAlgorithm = cipherAlgorithm;
        this.keySize = keySize;
        this.keyPairGenerator = KeyUtil.getKeyPairGenerator(this.algorithm);
        this.keyFactory = KeyUtil.getKeyFactory(this.algorithm);
        this.signature = KeyUtil.getSignature(this.signAlgorithm);
        this.cipher = KeyUtil.getCipher(this.cipherAlgorithm);
    }

    @Override
    public boolean checkKeyPair(String base64OrPemPrivateKey, String base64OrPemPublicKey) throws CertificateHelperException {
        if (StringUtil.isBlank(base64OrPemPrivateKey) || StringUtil.isBlank(base64OrPemPublicKey)) {
            log.debug("检查密钥对是否匹配: 密钥为空，结果 False");
            return false;
        }
        return checkKeyPair(PemUtil.readPemOrBase64Content(base64OrPemPrivateKey), PemUtil.readPemOrBase64Content(base64OrPemPublicKey));
    }

    @Override
    public boolean checkKeyPair(PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo) throws CertificateHelperException {
        if (Objects.isNull(privateKey) || Objects.isNull(subjectPublicKeyInfo)) {
            log.debug("检查密钥对是否匹配: 密钥为空，结果 False");
            return false;
        }
        return checkKeyPair(privateKey, convertToPublicKey(subjectPublicKeyInfo));

    }

    @Override
    public boolean checkKeyPair(PrivateKeyInfo privateKeyInfo, PublicKey publicKey) throws CertificateHelperException {
        if (Objects.isNull(privateKeyInfo) || Objects.isNull(publicKey)) {
            log.debug("检查密钥对是否匹配: 密钥为空，结果 False");
            return false;
        }
        return checkKeyPair(convertToPrivateKey(privateKeyInfo), publicKey);
    }

    @Override
    public boolean checkKeyPair(PrivateKeyInfo privateKeyInfo, SubjectPublicKeyInfo subjectPublicKeyInfo) throws CertificateHelperException {
        if (Objects.isNull(privateKeyInfo) || Objects.isNull(subjectPublicKeyInfo)) {
            log.debug("检查密钥对是否匹配: 密钥为空，结果 False");
            return false;
        }
        return checkKeyPair(convertToPrivateKey(privateKeyInfo), convertToPublicKey(subjectPublicKeyInfo));
    }

    @Override
    public boolean checkKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        if (Objects.isNull(privateKey) | Objects.isNull(publicKey)) {
            log.debug("检查密钥对是否匹配: 密钥为空，结果 False");
            return false;
        }
        if (!algorithm.equalsIgnoreCase(privateKey.getAlgorithm())
                || !algorithm.equalsIgnoreCase(privateKey.getAlgorithm())) {
            log.debug("检查密钥对是否匹配: 密钥非 「{}」算法，结果 False", algorithm);
            return false;
        }
        return checkKeyPair(privateKey.getEncoded(), publicKey.getEncoded());
    }

    @Override
    public boolean checkKeyPair(byte[] privateKey, byte[] publicKey) throws CertificateHelperException {
        if (Objects.isNull(privateKey) || Objects.isNull(publicKey) || privateKey.length <= 0 || publicKey.length <= 0) {
            log.debug("检查密钥对是否匹配: 密钥为空，结果 False");
            return false;
        }
        PublicKey anotherPublicKey;
        try {
            anotherPublicKey = convertPrivateKeyToPublicKey(privateKey);
        } catch (KeyHelperException e) {
            log.debug("检查密钥对是否匹配: 转换私钥时异常，结果 False");
            return false;
        }
        String base64PublicKey = Base64Util.encode2String(publicKey);
        String base64AnotherPublicKey;
        try {
            base64AnotherPublicKey = KeyUtil.convertPublicKeyToBase64String(anotherPublicKey);
        } catch (UtilException e) {
            throw new KeyHelperException("转换异常", e);
        }
        log.debug("检查密钥对是否匹配: 公钥 Base64 编码：「{}」", base64AnotherPublicKey);
        log.debug("检查密钥对是否匹配: 从私钥提取/生成的公钥 Base64 编码：「{}」", base64AnotherPublicKey);
        boolean check = base64PublicKey.equals(base64AnotherPublicKey);
        log.info("检查密钥对是否匹配: 结果「{}」", check);
        return check;
    }

    @Override
    public PrivateKey convertToPrivateKey(String base64OrPemPrivateKey) throws KeyHelperException {
        return convertToPrivateKey(PemUtil.readPemOrBase64Content(base64OrPemPrivateKey));
    }

    @Override
    public PrivateKey convertToPrivateKey(PrivateKeyInfo privateKeyInfo) throws KeyHelperException {
        log.info("私钥信息转换成私钥");
        if (Objects.isNull(privateKeyInfo)) {
            log.error("私钥信息转换成私钥: 私钥信息不能为空");
            throw new KeyHelperException("私钥信息转换成私钥: 私钥信息不能为空");
        }
        return convertToPrivateKey(getEncoded(privateKeyInfo));
    }

    @Override
    public PrivateKey convertToPrivateKey(byte[] privateKey) throws CertificateHelperException {
        if (Objects.isNull(privateKey) || privateKey.length == 0) {
            log.error("私钥数据转换成私钥: 私钥信息不能为空");
            throw new KeyHelperException("私钥数据转换成私钥: 私钥信息不能为空");
        }
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        PrivateKey convertPrivateKey;
        try {
            convertPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("私钥数据转换成私钥: 无效的密钥规范异常", e);
            throw new KeyHelperException("私钥数据转换成私钥: 无效的密钥规范异常", e);
        }
        log.info("私钥数据转换成私钥: 成功");
        return convertPrivateKey;
    }

    @Override
    public PrivateKeyInfo convertToPrivateKeyInfo(PrivateKey privateKey) throws KeyHelperException {
        try {
            return KeyUtil.convertPrivateKeyToPrivateKeyInfo(privateKey);
        } catch (UtilException e) {
            throw new KeyHelperException("转换异常", e);
        }
    }

    @Override
    public PublicKey convertToPublicKey(String base64OrPemPublicKey) throws KeyHelperException {
        return convertToPublicKey(PemUtil.readPemOrBase64Content(base64OrPemPublicKey));
    }

    @Override
    public PublicKey convertToPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws KeyHelperException {
        log.info("公钥信息转换成公钥");
        if (Objects.isNull(subjectPublicKeyInfo)) {
            log.error("公钥信息不能为空");
            throw new KeyHelperException("公钥信息不能为空");
        }
        return convertToPublicKey(getEncoded(subjectPublicKeyInfo));
    }

    @Override
    public PublicKey convertToPublicKey(byte[] publicKey) throws CertificateHelperException {
        if (Objects.isNull(publicKey) || publicKey.length == 0) {
            log.error("公钥数据转换成公钥：公钥数据不能为空");
            throw new KeyHelperException("公钥数据转换成公钥：公钥数据不能为空");
        }
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey convertPublicKey;
        try {
            convertPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("公钥数据转换成公钥：无效的密钥规范异常", e);
            throw new KeyHelperException("公钥数据转换成公钥：无效的密钥规范异常", e);
        }
        log.info("公钥数据转换成公钥：成功");
        return convertPublicKey;
    }

    @Override
    public PublicKey convertToPublicKey(PrivateKey privateKey) throws KeyHelperException {
        log.info("从私钥中提取/生成公钥");
        if (Objects.isNull(privateKey)) {
            log.error("私钥不能为空");
            throw new KeyHelperException("私钥不能为空");
        }
        return doConvertPrivateKey2PublicKey(privateKey);
    }

    @Override
    public PublicKey convertPrivateKeyToPublicKey(byte[] privateKey) throws CertificateHelperException {
        return convertToPublicKey(convertToPrivateKey(privateKey));
    }

    @Override
    public SubjectPublicKeyInfo convertToSubjectPublicKeyInfo(PublicKey publicKey) throws CertificateHelperException {
        try {
            return KeyUtil.convertPublicKeyToSubjectPublicKeyInfo(publicKey);
        } catch (UtilException e) {
            throw new KeyHelperException("转换异常", e);
        }
    }

    @Override
    public String convertToString(PrivateKey privateKey) throws KeyHelperException {
        try {
            return KeyUtil.convertPrivateKeyToBase64String(privateKey);
        } catch (UtilException e) {
            throw new KeyHelperException("转换异常", e);
        }
    }

    @Override
    public String convertToPem(PrivateKey privateKey) throws KeyHelperException, UtilException {
        if (Objects.isNull(privateKey)) {
            throw new KeyHelperException("私钥不能为空");
        }
        return PemUtil.writePemString("PRIVATE KEY", privateKey.getEncoded());
    }

    @Override
    public String sign(String plainText, String charset, String base64OrPemPrivateKey) throws KeyHelperException {
        if (StringUtil.isBlank(charset)) {
            charset = IHelperConstant.DEFAULT_CHARSET;
        }
        if (StringUtil.isBlank(plainText) || StringUtil.isBlank(base64OrPemPrivateKey)) {
            throw new KeyHelperException("签名原文或者私钥字串数据不能为空");
        }
        log.info("签名，算法为 [{}], 字符集为 [{}]", algorithm, charset);
        PrivateKey privateKey = convertToPrivateKey(base64OrPemPrivateKey);
        byte[] signData;
        try {
            signData = sign(plainText.getBytes(charset), privateKey);
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        String base64Sign = Base64Util.encode2String(signData, charset);
        log.info("签名成功, 结果「{}」", base64Sign);
        return base64Sign;
    }

    @Override
    public byte[] sign(byte[] plainText, PrivateKey privateKey) throws KeyHelperException {
        if (Objects.isNull(plainText) || plainText.length <= 0 || Objects.isNull(privateKey)) {
            throw new KeyHelperException("签名原文或者私钥数据不能为空");
        }
        try {
            signature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        try {
            signature.update(plainText);
            return signature.sign();
        } catch (SignatureException e) {
            log.error("签名异常", e);
            throw new KeyHelperException("签名异常", e);
        }
    }

    @Override
    public byte[] sign(byte[] plainText, byte[] privateKey) throws KeyHelperException {
        if (Objects.isNull(plainText) || plainText.length <= 0 || Objects.isNull(privateKey) || privateKey.length <= 0) {
            throw new KeyHelperException("签名原文或者私钥数据不能为空");
        }
        return sign(plainText, convertToPrivateKey(privateKey));
    }

    @Override
    public boolean verify(String plainText, String charset, String base64OrPemPublicKey, String base64Signature) throws KeyHelperException {
        if (StringUtil.isBlank(charset)) {
            charset = IHelperConstant.DEFAULT_CHARSET;
        }
        if (StringUtil.isBlank(plainText) || StringUtil.isBlank(base64OrPemPublicKey) || StringUtil.isBlank(base64Signature)) {
            throw new KeyHelperException("签名原文或者公钥字串或者签名不能为空");
        }
        log.info("验签，签名算法为 [{}], 字符集为 [{}]", signAlgorithm, charset);
        PublicKey publicKey = convertToPublicKey(base64OrPemPublicKey);
        byte[] signByte = Base64Util.decode2byte(base64Signature);
        boolean verify;
        try {
            verify = verify(plainText.getBytes(charset), publicKey, signByte);
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        log.info("签名成功, 结果「{}」", verify);
        return verify;
    }

    @Override
    public boolean verify(byte[] content, PublicKey publicKey, byte[] sign) throws KeyHelperException {
        try {
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        try {
            signature.update(content);
            return signature.verify(sign);
        } catch (SignatureException e) {
            log.error("签名异常", e);
            throw new KeyHelperException("签名异常", e);
        }
    }

    @Override
    public boolean verify(byte[] plainText, byte[] publicKey, byte[] signature) throws KeyHelperException {
        return verify(plainText, convertToPublicKey(publicKey), signature);
    }

    @Override
    public String encrypt(String plainText, String charset, String base64OrPemPublicKey) throws KeyHelperException {
        if (StringUtil.isBlank(charset)) {
            charset = IHelperConstant.DEFAULT_CHARSET;
        }
        if (StringUtil.isBlank(plainText) || StringUtil.isBlank(base64OrPemPublicKey)) {
            throw new KeyHelperException("加密原文或者公钥字串不能为空");
        }
        log.info("加密，加密算法为 [{}], 字符集为 [{}]", cipherAlgorithm, charset);
        byte[] encrypt;
        try {
            encrypt = encrypt(plainText.getBytes(charset), convertToPublicKey(base64OrPemPublicKey));
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        String base64CipherText = Base64Util.encode2String(encrypt, charset);
        log.info("加密成功, 结果「{}」", base64CipherText);
        return base64CipherText;
    }

    @Override
    public byte[] encrypt(byte[] plainText, PublicKey publicKey) throws KeyHelperException {
        if (Objects.isNull(plainText) || plainText.length <= 0 || Objects.isNull(publicKey)) {
            throw new KeyHelperException("加密字串与公钥钥不能为空");
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        return doCipher(plainText);
    }

    @Override
    public byte[] encrypt(byte[] plainText, byte[] publicKey) throws KeyHelperException {
        if (Objects.isNull(plainText) || plainText.length <= 0 || Objects.isNull(publicKey) || publicKey.length <= 0) {
            throw new KeyHelperException("加密字串与公钥钥不能为空");
        }
        return encrypt(plainText, convertToPublicKey(publicKey));
    }

    @Override
    public String decrypt(String base64CipherText, String charset, String base64OrPemPrivateKey) throws KeyHelperException {
        if (StringUtil.isBlank(charset)) {
            charset = IHelperConstant.DEFAULT_CHARSET;
        }
        if (StringUtil.isBlank(base64CipherText) || StringUtil.isBlank(base64OrPemPrivateKey)) {
            throw new KeyHelperException("加密数据或者私钥字串不能为空");
        }
        log.info("解密，加密算法为 [{}], 字符集为 [{}]", cipherAlgorithm, charset);
        byte[] cipherText = Base64Util.decode2byte(base64CipherText);

        byte[] decrypt = decrypt(cipherText, convertToPrivateKey(base64OrPemPrivateKey));
        String plainText;
        try {
            plainText = new String(decrypt, charset);
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        log.info("解密成功");
        return plainText;
    }

    @Override
    public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws KeyHelperException {
        if (Objects.isNull(cipherText) || cipherText.length <= 0 || Objects.isNull(privateKey)) {
            throw new KeyHelperException("解密字串与私钥不能为空");
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥异常", e);
            throw new KeyHelperException("无效的密钥异常", e);
        }

        return doCipher(cipherText);
    }


    @Override
    public byte[] decrypt(byte[] cipherText, byte[] privateKey) throws KeyHelperException {
        if (Objects.isNull(cipherText) || cipherText.length <= 0 || Objects.isNull(privateKey) || privateKey.length <= 0) {
            throw new KeyHelperException("解密字串与私钥不能为空");
        }
        return decrypt(cipherText, convertToPrivateKey(privateKey));
    }


    @Override
    public String convertToPkcs1Pem(PrivateKey privateKey) throws KeyHelperException {
        log.info("私钥转换成 PKCS#1 格式的 PEM 字串");
        byte[] data = getPkcs1PrivateData(privateKey);
        String pemPrivateKey = PemUtil.writePemString(algorithm.toUpperCase() + " PRIVATE KEY", data);
        log.info("私钥转换成 PKCS#1 格式的 PEM 字串成功");
        return pemPrivateKey;
    }


    @Override
    public String convertToString(PublicKey publicKey) throws KeyHelperException {
        try {
            return KeyUtil.convertPublicKeyToBase64String(publicKey);
        } catch (UtilException e) {
            throw new KeyHelperException("转换异常", e);
        }
    }

    @Override
    public String convertToPem(PublicKey publicKey) throws KeyHelperException {
        if (Objects.isNull(publicKey)) {
            throw new KeyHelperException("公钥不能为空");
        }
        try {
            return PemUtil.writePemString("PUBLIC KEY", publicKey.getEncoded());
        } catch (UtilException e) {
            throw new KeyHelperException(e);
        }
    }


    @Override
    public String convertToPkcs1String(PrivateKey privateKey) throws KeyHelperException {
        log.info("私钥转换成 Base64 PKCS#1 格式的字串");
        byte[] data = getPkcs1PrivateData(privateKey);
        String base64PrivateKey = Base64Util.encode2String(data);
        log.info("私钥转换成 Base64 PKCS#1 格式的字串成功");
        return base64PrivateKey;
    }

    /**
     * 从 {@link PrivateKey} 中解析 {@link PublicKey}
     *
     * @param privateKey 私钥
     * @return 公钥
     * @throws KeyHelperException 证书/密钥帮助类异常
     */
    protected abstract PublicKey doConvertPrivateKey2PublicKey(PrivateKey privateKey) throws KeyHelperException;

    private byte[] doCipher(byte[] plainText) {
        byte[] encrypt;
        try {
            encrypt = cipher.doFinal(plainText);
        } catch (IllegalBlockSizeException e) {
            log.error("非法块大小异常", e);
            throw new KeyHelperException("非法块大小异常", e);
        } catch (BadPaddingException e) {
            log.error("错误填充异常", e);
            throw new KeyHelperException("错误填充异常", e);
        }
        return encrypt;
    }

    private byte[] getPkcs1PrivateData(PrivateKey privateKey) {
        if (Objects.isNull(privateKey)) {
            log.error("私钥不能为空");
            throw new KeyHelperException("私钥不能为空");
        }
        byte[] data;
        try {
            data = KeyUtil.convertPrivateKeyToPkcs1(privateKey);
        } catch (UtilException e) {
            log.error("转换成 PKCS1 格式失败", e);
            throw new KeyHelperException("转换成 PKCS1 格式失败", e);
        }
        return data;
    }

    private byte[] getEncoded(Encodable encode) throws KeyHelperException {
        try {
            return encode.getEncoded();
        } catch (IOException e) {
            log.error("获取公钥字节码异常", e);
            throw new KeyHelperException("获取公钥字节码异常", e);
        }
    }
}

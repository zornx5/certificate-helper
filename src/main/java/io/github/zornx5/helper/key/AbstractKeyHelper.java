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
import io.github.zornx5.helper.exception.UtilException;
import io.github.zornx5.helper.util.Base64Util;
import io.github.zornx5.helper.util.KeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

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
import java.util.Base64;
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
        // TODO 判断和处理 PEM
        return checkKeyPair(Base64Util.decode2byte(base64OrPemPrivateKey), Base64Util.decode2byte(base64OrPemPublicKey));
    }

    @Override
    public boolean checkKeyPair(PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo) throws CertificateHelperException {
        return checkKeyPair(privateKey, convertSubjectPublicKeyInfo2PublicKey(subjectPublicKeyInfo));

    }

    @Override
    public boolean checkKeyPair(PrivateKeyInfo privateKeyInfo, PublicKey publicKey) throws CertificateHelperException {
        return checkKeyPair(convertPrivateKeyInfo2PrivateKey(privateKeyInfo), publicKey);
    }

    @Override
    public boolean checkKeyPair(PrivateKeyInfo privateKeyInfo, SubjectPublicKeyInfo subjectPublicKeyInfo) throws CertificateHelperException {
        return checkKeyPair(convertPrivateKeyInfo2PrivateKey(privateKeyInfo), convertSubjectPublicKeyInfo2PublicKey(subjectPublicKeyInfo));
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
            anotherPublicKey = convertPrivateKey2PublicKey(privateKey);
        } catch (KeyHelperException e) {
            log.debug("检查密钥对是否匹配: 转换私钥时异常，结果 False");
            return false;
        }
        String base64PublicKey = Base64Util.encode2String(publicKey);
        String base64AnotherPublicKey = KeyUtil.convertPublicKey2Base64String(anotherPublicKey);
        log.debug("检查密钥对是否匹配: 公钥 Base64 编码：「{}」", base64AnotherPublicKey);
        log.debug("检查密钥对是否匹配: 从私钥提取/生成的公钥 Base64 编码：「{}」", base64AnotherPublicKey);
        boolean check = base64PublicKey.equals(base64AnotherPublicKey);
        log.info("检查密钥对是否匹配: 结果「{}」", check);
        return check;
    }

    @Override
    public PrivateKey convertString2PrivateKey(String base64OrPemPrivateKey) throws KeyHelperException {
        // TODO 判断和处理 PEM
        return convertData2PrivateKey(Base64Util.decode2byte(base64OrPemPrivateKey));
    }

    @Override
    public PrivateKeyInfo convertPrivateKey2PrivateKeyInfo(PrivateKey privateKey) throws UtilException {
        return KeyUtil.convertPrivateKey2PrivateKeyInfo(privateKey);
    }

    @Override
    public PrivateKey convertPrivateKeyInfo2PrivateKey(PrivateKeyInfo privateKeyInfo) throws KeyHelperException {
        log.info("私钥信息转换成私钥");
        if (Objects.isNull(privateKeyInfo)) {
            log.error("私钥信息转换成私钥: 私钥信息不能为空");
            throw new KeyHelperException("私钥信息转换成私钥: 私钥信息不能为空");
        }
        try {
            return convertData2PrivateKey(privateKeyInfo.getEncoded());
        } catch (IOException e) {
            log.error("获取私钥字节码异常", e);
            throw new KeyHelperException("获取私钥字节码异常", e);
        }
    }

    @Override
    public PrivateKey convertData2PrivateKey(byte[] privateKey) throws CertificateHelperException {
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
    public PublicKey convertBase64String2PublicKey(String base64OrPemPublicKey) throws KeyHelperException {
        // TODO 判断和处理 PEM
        return convertData2PublicKey(Base64Util.decode2byte(base64OrPemPublicKey));
    }

    @Override
    public PublicKey convertSubjectPublicKeyInfo2PublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws KeyHelperException {
        log.info("公钥信息转换成公钥");
        if (Objects.isNull(subjectPublicKeyInfo)) {
            log.error("公钥信息不能为空");
            throw new KeyHelperException("公钥信息不能为空");
        }
        try {
            return convertData2PublicKey(subjectPublicKeyInfo.getEncoded());
        } catch (IOException e) {
            log.error("获取公钥字节码异常", e);
            throw new KeyHelperException("获取公钥字节码异常", e);
        }
    }

    @Override
    public PublicKey convertData2PublicKey(byte[] publicKey) throws CertificateHelperException {
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
    public PublicKey convertPrivateKey2PublicKey(PrivateKey privateKey) throws KeyHelperException {
        log.info("从私钥中提取/生成公钥");
        if (Objects.isNull(privateKey)) {
            log.error("私钥不能为空");
            throw new KeyHelperException("私钥不能为空");
        }
        return doConvertPrivateKey2PublicKey(privateKey);
    }

    @Override
    public PublicKey convertPrivateKey2PublicKey(byte[] privateKey) throws CertificateHelperException {
        return convertPrivateKey2PublicKey(convertData2PrivateKey(privateKey));
    }


    @Override
    public String sign(String plainText, String charset, String base64OrPemPrivateKey) throws KeyHelperException {
        log.info("签名，算法为 [{}], 字符集为 [{}]", algorithm, charset);
        PrivateKey privateKey = convertString2PrivateKey(base64OrPemPrivateKey);
        byte[] signData;
        try {
            signData = sign(plainText.getBytes(charset), privateKey);
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        byte[] base64SignData = Base64.getEncoder().encode(signData);
        String base64Sign = new String(base64SignData);
        log.info("签名成功, 结果「{}」", base64Sign);
        return base64Sign;
    }

    @Override
    public byte[] sign(byte[] plainText, PrivateKey privateKey) throws KeyHelperException {
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
    public byte[] sign(byte[] plainText, byte[] privateKey) throws CertificateHelperException {
        return sign(plainText, convertData2PrivateKey(privateKey));
    }

    @Override
    public boolean verify(String plainText, String charset, String base64OrPemPublicKey, String base64Signature) throws KeyHelperException {
        log.info("验签，签名算法为 [{}], 字符集为 [{}]", signAlgorithm, charset);
        PublicKey publicKey = convertBase64String2PublicKey(base64OrPemPublicKey);
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
    public boolean verify(byte[] plainText, byte[] publicKey, byte[] signature) throws CertificateHelperException {
        return verify(plainText, convertData2PublicKey(publicKey), signature);
    }

    @Override
    public String encrypt(String plainText, String charset, String base64OrPemPublicKey) throws KeyHelperException {
        log.info("加密，加密算法为 [{}], 字符集为 [{}]", cipherAlgorithm, charset);
        byte[] encrypt;
        try {
            encrypt = encrypt(plainText.getBytes(charset), convertBase64String2PublicKey(base64OrPemPublicKey));
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        String base64CipherText = Base64Util.encode2String(encrypt);
        log.info("加密成功, 结果「{}」", base64CipherText);
        return base64CipherText;
    }

    @Override
    public byte[] encrypt(byte[] plainText, PublicKey publicKey) throws CertificateHelperException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
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

    @Override
    public byte[] encrypt(byte[] plainText, byte[] publicKey) throws CertificateHelperException {
        return encrypt(plainText, convertData2PublicKey(publicKey));
    }

    @Override
    public String decrypt(String base64CipherText, String charset, String base64OrPemPrivateKey) throws KeyHelperException {
        log.info("解密，加密算法为 [{}], 字符集为 [{}]", cipherAlgorithm, charset);
        byte[] cipherText = Base64Util.decode2byte(base64CipherText);

        byte[] decrypt = decrypt(cipherText, convertString2PrivateKey(base64OrPemPrivateKey));
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
    public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws CertificateHelperException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥异常", e);
            throw new KeyHelperException("无效的密钥异常", e);
        }

        byte[] plainTextByte;
        try {
            plainTextByte = cipher.doFinal(cipherText);
        } catch (IllegalBlockSizeException e) {
            log.error("非法块大小异常", e);
            throw new KeyHelperException("非法块大小异常", e);
        } catch (BadPaddingException e) {
            log.error("错误填充异常", e);
            throw new KeyHelperException("错误填充异常", e);
        }
        return plainTextByte;
    }


    @Override
    public byte[] decrypt(byte[] cipherText, byte[] privateKey) throws CertificateHelperException {
        return decrypt(cipherText, convertData2PrivateKey(privateKey));
    }


    @Override
    public String convertToPkcs1Pem(PrivateKey privateKey) throws KeyHelperException {
        log.info("私钥转换成 PKCS#1 格式的 PEM 字串");
        if (privateKey == null) {
            log.error("私钥不能为空");
            throw new KeyHelperException("私钥不能为空");
        }
        byte[] data;
        try {
            data = KeyUtil.convertPkcs8ToPkcs1(privateKey);
        } catch (IOException e) {
            log.error("转换成 PKCS1 格式失败", e);
            throw new KeyHelperException("转换成 PKCS1 格式失败", e);
        }
        String pemPrivateKey = KeyUtil.write2Pem(algorithm.toUpperCase() + " PRIVATE KEY", data);
        log.info("私钥转换成 PKCS#1 格式的 PEM 字串成功");
        return pemPrivateKey;
    }

    @Override
    public String convertToBase64Pkcs1String(PrivateKey privateKey) throws KeyHelperException {
        log.info("私钥转换成 Base64 PKCS#1 格式的字串");
        if (privateKey == null) {
            log.error("私钥不能为空");
            throw new KeyHelperException("私钥不能为空");
        }
        byte[] data;
        try {
            data = KeyUtil.convertPkcs8ToPkcs1(privateKey);
        } catch (IOException e) {
            log.error("转换成 PKCS1 格式失败", e);
            throw new KeyHelperException("转换成 PKCS1 格式失败", e);
        }
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
}

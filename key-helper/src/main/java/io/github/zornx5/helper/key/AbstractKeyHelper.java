package io.github.zornx5.helper.key;

import io.github.zornx5.helper.key.exception.KeyHelperException;
import io.github.zornx5.helper.util.KeyUtil;
import io.github.zornx5.helper.util.StringUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
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
    public boolean checkKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        log.info("检查密钥对是否匹配");
        if (privateKey == null || publicKey == null) {
            return false;
        }
        if (!algorithm.equalsIgnoreCase(privateKey.getAlgorithm())
                || !algorithm.equalsIgnoreCase(privateKey.getAlgorithm())) {
            return false;
        }
        PublicKey parsePublicKey;
        try {
            parsePublicKey = convertPrivateKey2PublicKey(privateKey);
        } catch (KeyHelperException e) {
            log.error("转换异常", e);
            return false;
        }
        String base64PublicKey = KeyUtil.convertPublicKey2Base64String(publicKey);
        String base64ParsePublicKey = KeyUtil.convertPublicKey2Base64String(parsePublicKey);
        log.debug("公钥 Base64 编码：「{}」", base64ParsePublicKey);
        log.debug("私钥提取的公钥 Base64 编码：「{}」", base64ParsePublicKey);
        boolean equals = base64PublicKey.equals(base64ParsePublicKey);
        log.info("检查密钥对是否匹配完成，结果「{}」", equals);
        return equals;
    }

    @Override
    public PrivateKey convertPrivateKeyInfo2PrivateKey(PrivateKeyInfo privateKeyInfo) throws KeyHelperException {
        log.info("私钥信息转换成私钥");
        if (privateKeyInfo == null) {
            log.error("私钥信息不能为空");
            throw new KeyHelperException("私钥信息不能为空");
        }
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec;
        try {
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
        } catch (IOException e) {
            log.error("获取私钥字节码异常", e);
            throw new KeyHelperException("获取私钥字节码异常", e);
        }
        PrivateKey privateKey;
        try {
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        log.info("私钥信息转换成私钥成功");
        return privateKey;
    }

    @Override
    public PublicKey convertPrivateKey2PublicKey(PrivateKey privateKey) throws KeyHelperException {
        log.info("从私钥中提取/生成公钥");
        if (privateKey == null) {
            log.error("私钥不能为空");
            throw new KeyHelperException("私钥不能为空");
        }
        return doConvertPrivateKey2PublicKey(privateKey);
    }

    @Override
    public PublicKey convertSubjectPublicKeyInfo2PublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws KeyHelperException {
        log.info("公钥信息转换成公钥");
        if (subjectPublicKeyInfo == null) {
            log.error("公钥信息不能为空");
            throw new KeyHelperException("公钥信息不能为空");
        }
        X509EncodedKeySpec x509EncodedKeySpec;
        try {
            x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        } catch (IOException e) {
            log.error("获取公钥字节码异常", e);
            throw new KeyHelperException("获取公钥字节码异常", e);
        }
        PublicKey publicKey;
        try {
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        log.info("公钥信息转换成公钥成功");
        return publicKey;
    }

    @Override
    public PrivateKey convertBase64String2PrivateKey(String base64PrivateKey) throws KeyHelperException {
        log.info("Base64 编码私钥转换成私钥");
        if (StringUtil.isBlank(base64PrivateKey)) {
            log.error("Base64 编码私钥不能为空");
            throw new KeyHelperException("Base64 编码私钥不能为空");
        }
        byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey privateKey;
        try {
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        log.info("Base64 编码私钥转换成私钥成功");
        return privateKey;
    }

    @Override
    public PublicKey convertBase64String2PublicKey(String base64PublicKey) throws KeyHelperException {
        log.info("Base64 编码公钥转换成公钥");
        if (StringUtil.isBlank(base64PublicKey)) {
            log.error("Base64 编码公钥不能为空");
            throw new KeyHelperException("Base64 编码公钥不能为空");
        }
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey.getBytes(StandardCharsets.UTF_8));
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey;
        try {
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        log.info("Base64 编码公钥转换成公钥成功");
        return publicKey;
    }

    @Override
    public String sign(String content, String charset, String base64PrivateKey) throws KeyHelperException {
        log.info("签名，算法为 [{}], 字符集为 [{}]", algorithm, charset);
        PrivateKey privateKey = convertBase64String2PrivateKey(base64PrivateKey);
        byte[] signData;
        try {
            signData = sign(content.getBytes(charset), privateKey);
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
    public byte[] sign(byte[] contentData, PrivateKey privateKey) throws KeyHelperException {
        try {
            signature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        try {
            signature.update(contentData);
            return signature.sign();
        } catch (SignatureException e) {
            log.error("签名异常", e);
            throw new KeyHelperException("签名异常", e);
        }
    }

    @Override
    public boolean verify(String content, String charset, String base64PublicKey, String base64Sign) throws KeyHelperException {
        log.info("验签，签名算法为 [{}], 字符集为 [{}]", signAlgorithm, charset);
        PublicKey publicKey = convertBase64String2PublicKey(base64PublicKey);
        byte[] signByte = Base64.getDecoder().decode(base64Sign);
        boolean verify;
        try {
            verify = verify(content.getBytes(charset), signByte, publicKey);
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        log.info("签名成功, 结果「{}」", verify);
        return verify;
    }

    @Override
    public boolean verify(byte[] contentData, byte[] signData, PublicKey publicKey) throws KeyHelperException {
        try {
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        try {
            signature.update(contentData);
            return signature.verify(signData);
        } catch (SignatureException e) {
            log.error("签名异常", e);
            throw new KeyHelperException("签名异常", e);
        }
    }

    @Override
    public String encrypt(String plainText, String charset, String base64PublicKey) throws KeyHelperException {
        log.info("加密，加密算法为 [{}], 字符集为 [{}]", cipherAlgorithm, charset);
        PublicKey publicKey = convertBase64String2PublicKey(base64PublicKey);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        byte[] encrypt;
        String base64CipherText;
        try {
            encrypt = cipher.doFinal(plainText.getBytes(charset));
            base64CipherText = new String(Base64.getEncoder().encode(encrypt), charset);
        } catch (IllegalBlockSizeException e) {
            log.error("非法块大小异常", e);
            throw new KeyHelperException("非法块大小异常", e);
        } catch (BadPaddingException e) {
            log.error("错误填充异常", e);
            throw new KeyHelperException("错误填充异常", e);
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        log.info("加密成功, 结果「{}」", base64CipherText);
        return base64CipherText;
    }

    @Override
    public String decrypt(String base64CipherText, String charset, String base64PrivateKey) throws KeyHelperException {
        log.info("解密，加密算法为 [{}], 字符集为 [{}]", cipherAlgorithm, charset);
        PrivateKey privateKey = convertBase64String2PrivateKey(base64PrivateKey);
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] cipherText = new byte[0];
        try {
            cipherText = Base64.getDecoder().decode(base64CipherText.getBytes(charset));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
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

        String plainText;
        try {
            plainText = new String(plainTextByte, charset);
        } catch (UnsupportedEncodingException e) {
            log.error("不支持的编码异常", e);
            throw new KeyHelperException("不支持的编码异常", e);
        }
        log.info("解密成功");
        return plainText;
    }

    /**
     * 转换成 PEM 字串
     *
     * @param privateKey 私钥
     * @return PEM 字串
     * @throws KeyHelperException 密钥帮助异常
     */
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
        String pemPrivateKey = KeyUtil.convertToPem(algorithm.toUpperCase() + " PRIVATE KEY", data);
        log.info("私钥转换成 PKCS#1 格式的 PEM 字串成功");
        return pemPrivateKey;
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

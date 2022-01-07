package io.github.zornx5.helper.key.impl;

import io.github.zornx5.helper.key.AbstractKeyHelper;
import io.github.zornx5.helper.key.exception.KeyHelperException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static io.github.zornx5.helper.constant.IHelperConstant.RSA_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.RSA_DEFAULT_CIPHER_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.RSA_DEFAULT_KEY_SIZE;
import static io.github.zornx5.helper.constant.IHelperConstant.RSA_DEFAULT_SIGN_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.RSA_MAX_KEY_SIZE;
import static io.github.zornx5.helper.constant.IHelperConstant.RSA_MIN_KEY_SIZE;

/**
 * RSA 密钥帮助类
 *
 * @author zornx5
 */
@Slf4j
public class RsaKeyHelper extends AbstractKeyHelper {

    public RsaKeyHelper() {
        super(RSA_ALGORITHM, RSA_DEFAULT_SIGN_ALGORITHM, RSA_DEFAULT_CIPHER_ALGORITHM, RSA_DEFAULT_KEY_SIZE);
    }

    @Override
    public KeyPair generateKeyPair() {
        log.debug("使用默认密钥大小「{}」生成「{}」密钥对", keySize, algorithm);
        return generateKeyPair(RSA_DEFAULT_KEY_SIZE);
    }

    @Override
    public KeyPair generateKeyPair(int keySize) {
        log.debug("生成「{}」密钥对有效区间为 [{},{}] 且需要是「{}」的整数倍",
                algorithm, RSA_MIN_KEY_SIZE, RSA_MAX_KEY_SIZE, RSA_MIN_KEY_SIZE);
        if (keySize > RSA_MIN_KEY_SIZE && keySize < RSA_MAX_KEY_SIZE && keySize % RSA_MIN_KEY_SIZE == 0) {
            log.debug("设置生成「{}」密钥大小为「{}」", algorithm, keySize);
            this.keySize = keySize;
        }
        log.info("生成「{}」密钥对，密钥大小「{}」", algorithm, this.keySize);
        keyPairGenerator.initialize(this.keySize);
        KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
        log.info("生成「{}」密钥对成功", algorithm);
        log.debug("密钥内容：{}", generateKeyPair);
        return generateKeyPair;
    }

    public int getKeySize(PrivateKey privateKey) throws KeyHelperException {
        if (algorithm.equalsIgnoreCase(privateKey.getAlgorithm())) {
            log.info("获取「{}」私钥密钥大小", algorithm);
            RSAPrivateKeySpec keySpec;
            try {
                keySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            } catch (InvalidKeySpecException e) {
                log.error("无效的密钥规范异常", e);
                throw new KeyHelperException("无效的密钥规范异常", e);
            }
            int keySize = keySpec.getModulus().toString(2).length();
            log.info("获取密钥大小成功，密钥大小为 「{}」", keySize);
            return keySize;
        } else {
            throw new KeyHelperException("本实现不支持此算法：" + privateKey.getAlgorithm() + " 私钥");
        }
    }

    public int getKeySize(PublicKey publicKey) throws KeyHelperException {
        if (algorithm.equalsIgnoreCase(publicKey.getAlgorithm())) {
            log.info("获取「{}」公钥密钥大小", algorithm);
            RSAPublicKeySpec keySpec;
            try {
                keySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            } catch (InvalidKeySpecException e) {
                log.error("无效的密钥规范异常", e);
                throw new KeyHelperException("无效的密钥规范异常", e);
            }
            int keySize = keySpec.getModulus().toString(2).length();
            log.info("获取密钥大小成功，密钥大小为 「{}」", keySize);
            return keySize;
        } else {
            throw new KeyHelperException("本实现不支持此算法：" + publicKey.getAlgorithm() + " 公钥");
        }
    }

    @Override
    protected PublicKey doConvertPrivateKey2PublicKey(PrivateKey privateKey) throws KeyHelperException {
        if (algorithm.equalsIgnoreCase(privateKey.getAlgorithm())) {
            log.info("从「{}」私钥中提取/生成公钥", algorithm);
            BCRSAPrivateCrtKey rsaPrivateKey = (BCRSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent());
            PublicKey publicKey;
            try {
                publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
            } catch (InvalidKeySpecException e) {
                log.error("无效的密钥规范异常", e);
                throw new KeyHelperException("无效的密钥规范异常", e);
            }
            log.info("从私钥中提取/生成公钥成功");
            return publicKey;
        } else {
            throw new KeyHelperException("本实现不支持此算法：" + algorithm);
        }
    }

    @Override
    public PrivateKey convertPkcs1ToPkcs8(byte[] pkcs1PrivateKey) throws KeyHelperException {
        log.info("转换「{}」旧 PKCS#1 （Openssl）私钥成 PKCS#8 （Java）格式", algorithm);
        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(pkcs1PrivateKey);
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());
        PrivateKey privateKey;
        try {
            privateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        log.info("转换旧 PKCS#1 （Openssl）私钥成 PKCS#8 （Java）格式成功");
        return privateKey;
    }
}
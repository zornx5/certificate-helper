package io.github.zornx5.helper.key.impl;

import io.github.zornx5.helper.key.AbstractKeyHelper;
import io.github.zornx5.helper.key.exception.KeyHelperException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static io.github.zornx5.helper.constant.IHelperConstant.EC_DEFAULT_CIPHER_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.EC_DEFAULT_KEY_SIZE;
import static io.github.zornx5.helper.constant.IHelperConstant.EC_DEFAULT_SIGN_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.SM2_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.SM2_DEFAULT_KEY_SIZE;

/**
 * EC 密钥帮助类
 *
 * @author zornx5
 */
@Slf4j
public class EcKeyHelper extends AbstractKeyHelper {

    protected String ecCurve = "secp256k1";

    public EcKeyHelper() {
        super(SM2_ALGORITHM, EC_DEFAULT_SIGN_ALGORITHM, EC_DEFAULT_CIPHER_ALGORITHM, EC_DEFAULT_KEY_SIZE);
    }

    public EcKeyHelper(String algorithm, String signAlgorithm, String cipherAlgorithm, int keySize, String ecCurve) {
        super(algorithm, signAlgorithm, cipherAlgorithm, keySize);
        this.ecCurve = ecCurve;
    }

    @Override
    public KeyPair generateKeyPair() throws KeyHelperException {
        log.debug("使用默认密钥大小「{}」生成「{}」密钥对", keySize, algorithm);
        return generateKeyPair(SM2_DEFAULT_KEY_SIZE);
    }

    @Override
    public KeyPair generateKeyPair(int keySize) throws KeyHelperException {
        keySize = SM2_DEFAULT_KEY_SIZE;
        log.debug("生成「{}」密钥对有效值仅为 [{}]", algorithm, keySize);
        log.info("生成「{}」密钥对，密钥大小「{}」", algorithm, this.keySize);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecCurve);
        log.debug("密钥参数：{}", ecGenParameterSpec);
        keyPairGenerator.initialize(keySize);
        try {
            keyPairGenerator.initialize(ecGenParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            log.error("无效的算法参数异常", e);
            throw new KeyHelperException("无效的算法参数异常", e);
        }
        KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
        log.info("生成「{}」密钥对成功", algorithm);
        log.debug("密钥内容：{}", generateKeyPair);
        return generateKeyPair;
    }

    @Override
    public PublicKey doConvertPrivateKey2PublicKey(PrivateKey privateKey) throws KeyHelperException {
        if (algorithm.equalsIgnoreCase(privateKey.getAlgorithm())) {
            log.info("从「{}」私钥中提取/生成公钥", algorithm);
            BCECPrivateKey ecPrivateKey = (BCECPrivateKey) privateKey;
            // EC 参数规范
            ECParameterSpec ecParameterSpec = ecPrivateKey.getParameters();
            // EC 域参数
            ECDomainParameters domainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                    ecParameterSpec.getG(), ecParameterSpec.getN(), ecParameterSpec.getH());
            // 私钥参数
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(ecPrivateKey.getD(),
                    domainParameters);
            // 公钥坐标
            ECPoint q = new FixedPointCombMultiplier().multiply(domainParameters.getG(), privateKeyParameters.getD());
            // 公钥参数
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(q, domainParameters);

            BCECPublicKey publicKey = new BCECPublicKey(algorithm, publicKeyParameters, ecParameterSpec, BouncyCastleProvider.CONFIGURATION);
            log.info("从私钥中提取/生成公钥成功");
            return publicKey;
        } else {
            throw new KeyHelperException("本实现不支持此算法：" + algorithm);
        }
    }

    @Override
    public PrivateKey convertPkcs1ToPkcs8(byte[] sec1PrivateKey) throws KeyHelperException {
        throw new KeyHelperException("此实现没有提供此方法");
    }
}
package io.github.zornx5.helper.key;

import io.github.zornx5.helper.key.exception.KeyHelperException;
import io.github.zornx5.helper.key.impl.EcKeyHelper;
import io.github.zornx5.helper.key.impl.RsaKeyHelper;
import io.github.zornx5.helper.key.impl.Sm2KeyHelper;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * 密钥帮助管理器
 *
 * @author zornx5
 */
public class KeyHelperManager {

    public static IKeyHelper getByName(String type) {
        String rsa = "RSA";
        String sm2 = "SM2";
        String ec = "EC";
        String ecIes = "ECIES";
        String ecDsa = "ECDSA";
        if (sm2.equalsIgnoreCase(type)) {
            return new Sm2KeyHelper();
        }
        if (ec.equalsIgnoreCase(type) || ecIes.equalsIgnoreCase(type) || ecDsa.equalsIgnoreCase(type)) {
            return new EcKeyHelper();
        }
        if (rsa.equalsIgnoreCase(type)) {
            return new RsaKeyHelper();
        }
        throw new KeyHelperException("暂不支持的算法");
    }

    /**
     * 根据公/私钥算法标识返回对应帮助类
     *
     * @param algorithmIdentifier 公/私钥算法标识
     * @return 帮助类
     * @throws KeyHelperException 密钥帮助异常
     */
    public static IKeyHelper getByAlgorithm(AlgorithmIdentifier algorithmIdentifier) throws KeyHelperException {
        if (algorithmIdentifier == null) {
            throw new KeyHelperException("algorithmIdentifier 为空");
        }
        ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
            // EC 私钥
            if (GMObjectIdentifiers.sm2p256v1.equals(algorithmIdentifier.getParameters())) {
                // SM2 私钥
                return new Sm2KeyHelper();
            }
            if (SECObjectIdentifiers.secp256k1.equals(algorithmIdentifier.getParameters())) {
                // 默认 EC 私钥
                return new EcKeyHelper();
            }
            throw new KeyHelperException("暂不支持的曲线算法");
        }
        if (GMObjectIdentifiers.sm2sign_with_sm3.equals(algorithm)) {
            // SM2 默认签名算法
            return new Sm2KeyHelper();
        }
        if (X9ObjectIdentifiers.ecdsa_with_SHA256.equals(algorithm)) {
            // EC 默认签名算法
            return new EcKeyHelper();
        }
        if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)) {
            // RSA 算法
            return new RsaKeyHelper();
        }
        if (PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algorithm)) {
            //  RSA 默认签名算法
            return new RsaKeyHelper();
        }
        throw new KeyHelperException("暂不支持的算法" + algorithm);
    }
}
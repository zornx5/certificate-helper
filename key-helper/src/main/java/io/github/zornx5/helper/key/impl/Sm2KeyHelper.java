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

package io.github.zornx5.helper.key.impl;

import io.github.zornx5.helper.key.exception.KeyHelperException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static io.github.zornx5.helper.constant.IHelperConstant.SM2_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.SM2_DEFAULT_CIPHER_ALGORITHM;
import static io.github.zornx5.helper.constant.IHelperConstant.SM2_DEFAULT_KEY_SIZE;
import static io.github.zornx5.helper.constant.IHelperConstant.SM2_DEFAULT_SIGN_ALGORITHM;

/**
 * SM2 密钥帮助类
 *
 * @author zornx5
 */
@Slf4j
public class Sm2KeyHelper extends EcKeyHelper {

    private final static byte[] USER_ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);

    public Sm2KeyHelper() {
        super(SM2_ALGORITHM, SM2_DEFAULT_SIGN_ALGORITHM, SM2_DEFAULT_CIPHER_ALGORITHM, SM2_DEFAULT_KEY_SIZE, "sm2p256v1");
    }

    @Override
    public byte[] sign(byte[] contentData, PrivateKey privateKey) throws KeyHelperException {
        AsymmetricKeyParameter ecParam;
        try {
            ecParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
        } catch (IOException e) {
            log.error("获取私钥字节码异常", e);
            throw new KeyHelperException("获取私钥字节码异常", e);
        }
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(true, new ParametersWithID(ecParam, USER_ID));
        sm2Signer.update(contentData, 0, contentData.length);
        try {
            return sm2Signer.generateSignature();
        } catch (CryptoException e) {
            log.error("加密异常", e);
            throw new KeyHelperException("加密异常", e);
        }
    }

    @Override
    public boolean verify(byte[] contentData, byte[] signData, PublicKey publicKey) throws KeyHelperException {
        AsymmetricKeyParameter ecParam;
        try {
            ecParam = ECUtil.generatePublicKeyParameter(publicKey);
        } catch (InvalidKeyException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(false, new ParametersWithID(ecParam, USER_ID));
        sm2Signer.update(contentData, 0, contentData.length);
        return sm2Signer.verifySignature(signData);
    }

    @Override
    public PrivateKey convertPkcs1ToPkcs8(byte[] sec1PrivateKey) throws KeyHelperException {
        log.info("转换「{}」旧 SEC.1 （Openssl）私钥成 PKCS#8 （Java）格式", algorithm);
        SM2P256V1Curve sm2P256V1Curve = new SM2P256V1Curve();
        BigInteger q = sm2P256V1Curve.getQ();
        BigInteger a = sm2P256V1Curve.getA().toBigInteger();
        BigInteger b = sm2P256V1Curve.getB().toBigInteger();
        EllipticCurve ellipticCurve = new EllipticCurve(new ECFieldFp(q), a, b);
        BigInteger order = sm2P256V1Curve.getOrder();
        BigInteger cofactor = sm2P256V1Curve.getCofactor();
        BigInteger gx = new BigInteger(
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
        BigInteger gy = new BigInteger(
                "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
        ECPoint point = sm2P256V1Curve.createPoint(gx, gy);

        java.security.spec.ECPoint ecPoint = new java.security.spec.ECPoint(
                point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger());
        java.security.spec.ECParameterSpec ecParameterSpec = new java.security.spec.ECParameterSpec(
                ellipticCurve, ecPoint, order, cofactor.intValue());
        ECCurve curve = EC5Util.convertCurve(ecParameterSpec.getCurve());

        X9ECParameters ecP = new X9ECParameters(
                curve,
                new X9ECPoint(EC5Util.convertPoint(curve, ecParameterSpec.getGenerator()), false),
                ecParameterSpec.getOrder(),
                BigInteger.valueOf(ecParameterSpec.getCofactor()),
                ecParameterSpec.getCurve().getSeed());
        X962Parameters x962Parameters = new X962Parameters(ecP);

        // EC 参数规范
        ASN1OctetString privateKey = new DEROctetString(sec1PrivateKey);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        //版本号
        vector.add(new ASN1Integer(0));
        //算法标识
        vector.add(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, x962Parameters));
        vector.add(privateKey);
        DERSequence derSequence = new DERSequence(vector);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec;
        try {
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(derSequence.getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            log.error("获取私钥字节码异常", e);
            throw new KeyHelperException("获取私钥字节码异常", e);
        }
        BCECPrivateKey bcecPrivateKey;
        try {
            bcecPrivateKey = (BCECPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            log.error("无效的密钥规范异常", e);
            throw new KeyHelperException("无效的密钥规范异常", e);
        }
        log.info("转换旧 SEC.1 （Openssl）私钥成 PKCS#8 （Java）格式成功");
        return bcecPrivateKey;
    }
}

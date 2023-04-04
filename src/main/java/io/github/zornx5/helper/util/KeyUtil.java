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

package io.github.zornx5.helper.util;

import io.github.zornx5.helper.GlobalBouncyCastleProvider;
import io.github.zornx5.helper.exception.UtilException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * 密钥工具类
 *
 * @author zornx5
 */
@Slf4j
public class KeyUtil {

    public static final Provider PROVIDER = GlobalBouncyCastleProvider.INSTANCE.getProvider();

    /**
     * 获取 {@link KeyPairGenerator}
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyPairGenerator}
     */
    public static KeyPairGenerator getKeyPairGenerator(String algorithm) throws UtilException {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = (null == PROVIDER)
                    ? KeyPairGenerator.getInstance(algorithm)
                    : KeyPairGenerator.getInstance(algorithm, PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new UtilException(e);
        }
        return keyPairGenerator;
    }

    /**
     * 获取 {@link KeyFactory}
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyFactory}
     */
    public static KeyFactory getKeyFactory(String algorithm) throws UtilException {
        KeyFactory keyFactory;
        try {
            keyFactory = (null == PROVIDER)
                    ? KeyFactory.getInstance(algorithm)
                    : KeyFactory.getInstance(algorithm, PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new UtilException(e);
        }
        return keyFactory;
    }

    /**
     * 获取 {@link Signature}
     *
     * @param signAlgorithm 签名算法
     * @return {@link Signature}
     */
    public static Signature getSignature(String signAlgorithm) throws UtilException {
        Signature signature;
        try {
            signature = (null == PROVIDER)
                    ? Signature.getInstance(signAlgorithm)
                    : Signature.getInstance(signAlgorithm, PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new UtilException(e);
        }
        return signature;
    }

    /**
     * 获取 {@link Cipher}
     *
     * @param cipherAlgorithm 加密算法
     * @return {@link Cipher}
     */
    public static Cipher getCipher(String cipherAlgorithm) throws UtilException {
        Cipher cipher;
        try {
            cipher = (null == PROVIDER)
                    ? Cipher.getInstance(cipherAlgorithm)
                    : Cipher.getInstance(cipherAlgorithm, PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UtilException(e);
        }
        return cipher;
    }


    public static PrivateKeyInfo convertPrivateKeyToPrivateKeyInfo(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new UtilException("私钥不能为空");
        }
        return PrivateKeyInfo.getInstance(privateKey.getEncoded());
    }

    public static SubjectPublicKeyInfo convertPublicKeyToSubjectPublicKeyInfo(PublicKey publicKey) {
        if (publicKey == null) {
            throw new UtilException("公钥不能为空");
        }
        return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    }

    public static String convertPrivateKeyToBase64String(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new UtilException("私钥不能为空");
        }
        return new String(Base64.getEncoder().encode(privateKey.getEncoded()), StandardCharsets.UTF_8);
    }

    public static String convertPrivateKeyInfoToBase64String(PrivateKeyInfo privateKeyInfo) {
        if (privateKeyInfo == null) {
            throw new UtilException("私钥信息不能为空");
        }
        byte[] privateKeyInfoEncoded;
        try {
            privateKeyInfoEncoded = privateKeyInfo.getEncoded();
        } catch (IOException e) {
            throw new UtilException("私钥信息获取编码错误", e);
        }
        return new String(Base64.getEncoder().encode(privateKeyInfoEncoded), StandardCharsets.UTF_8);
    }

    public static String convertPublicKeyToBase64String(PublicKey publicKey) {
        if (publicKey == null) {
            throw new UtilException("公钥不能为空");
        }
        return new String(Base64.getEncoder().encode(publicKey.getEncoded()), StandardCharsets.UTF_8);
    }

    public static String convertSubjectPublicKeyInfoToBase64String(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        if (subjectPublicKeyInfo == null) {
            throw new UtilException("公钥信息不能为空");
        }
        byte[] subjectPublicKeyInfoEncoded;
        try {
            subjectPublicKeyInfoEncoded = subjectPublicKeyInfo.getEncoded();
        } catch (IOException e) {
            throw new UtilException("公钥信息获取编码错误", e);
        }
        return new String(Base64.getEncoder().encode(subjectPublicKeyInfoEncoded), StandardCharsets.UTF_8);
    }

    public static byte[] convertPrivateKeyToPkcs1(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new UtilException("私钥不能为空");
        }
        byte[] pkcs1PrivateKey;
        try {
            pkcs1PrivateKey = convertPrivateKeyToPrivateKeyInfo(privateKey).parsePrivateKey().toASN1Primitive().getEncoded();
        } catch (IOException e) {
            throw new UtilException("解析成私钥错误", e);
        }
        return pkcs1PrivateKey;
    }

    public static String convertPrivateKeyToPkcs8Pem(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new UtilException("私钥不能为空");
        }
        byte[] data = privateKey.getEncoded();
        return PemUtil.writePemString("PRIVATE KEY", data);
    }

    public static String convertPublicKeyToPkcs8Pem(PublicKey publicKey) {
        if (publicKey == null) {
            throw new UtilException("公钥不能为空");
        }
        byte[] data = publicKey.getEncoded();
        return PemUtil.writePemString("PUBLIC KEY", data);
    }
}

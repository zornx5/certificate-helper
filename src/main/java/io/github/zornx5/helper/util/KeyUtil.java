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
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
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
     * 防止实例化
     */
    private KeyUtil() {
    }

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


    public static PrivateKeyInfo convertPrivateKey2PrivateKeyInfo(PrivateKey privateKey) {
        log.info("私钥转换成私钥信息");
        if (privateKey == null) {
            log.error("私钥不能为空");
            throw new UtilException("私钥不能为空");
        }
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        log.info("私钥转换成私钥信息成功");
        return privateKeyInfo;
    }

    public static SubjectPublicKeyInfo convertToSubjectPublicKeyInfo(PublicKey publicKey) {
        log.info("公钥转换成公钥信息");
        if (publicKey == null) {
            log.error("公钥不能为空");
            throw new UtilException("公钥不能为空");
        }
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        log.info("公钥转换成公钥信息成功");
        return subjectPublicKeyInfo;
    }

    public static String convertPrivateKey2Base64String(PrivateKey privateKey) {
        log.info("私钥转换成 Base64 编码私钥");
        if (privateKey == null) {
            log.error("私钥不能为空");
            throw new UtilException("私钥不能为空");
        }
        String base64PrivateKey = new String(Base64.getEncoder().encode(privateKey.getEncoded()), StandardCharsets.UTF_8);
        log.info("私钥转换成 Base64 编码私钥成功");
        return base64PrivateKey;
    }

    public static String convertPrivateKeyInfo2Base64String(PrivateKeyInfo privateKeyInfo) throws IOException {
        log.info("私钥信息转换成 Base64 编码私钥");
        if (privateKeyInfo == null) {
            log.error("私钥信息不能为空");
            throw new UtilException("私钥信息不能为空");
        }
        String base64PrivateKey = new String(Base64.getEncoder().encode(privateKeyInfo.getEncoded()), StandardCharsets.UTF_8);
        log.info("私钥转换成 Base64 编码私钥成功");
        return base64PrivateKey;
    }

    public static String convertPublicKey2Base64String(PublicKey publicKey) {
        log.info("公钥转换成 Base64 编码公钥");
        if (publicKey == null) {
            log.error("公钥不能为空");
            throw new UtilException("公钥不能为空");
        }
        String base64PublicKey = new String(Base64.getEncoder().encode(publicKey.getEncoded()), StandardCharsets.UTF_8);
        log.info("公钥转换成 Base64 编码公钥成功");
        return base64PublicKey;
    }

    public static String convertSubjectPublicKeyInfo2Base64String(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        log.info("公钥信息转换成 Base64 编码公钥");
        if (subjectPublicKeyInfo == null) {
            log.error("公钥信息不能为空");
            throw new UtilException("公钥信息不能为空");
        }
        String base64PublicKey = new String(Base64.getEncoder().encode(subjectPublicKeyInfo.getEncoded()), StandardCharsets.UTF_8);
        log.info("公钥转换成 Base64 编码公钥成功");
        return base64PublicKey;
    }

    public static byte[] convertPkcs8ToPkcs1(PrivateKey privateKey) throws IOException {
        log.info("私钥转换成 PKCS#1 编码私钥数组");
        if (privateKey == null) {
            log.error("私钥不能为空");
            throw new UtilException("私钥不能为空");
        }
        byte[] pkcs1PrivateKey = convertPrivateKey2PrivateKeyInfo(privateKey).parsePrivateKey().toASN1Primitive().getEncoded();
        log.info("私钥转换成 PKCS#1 编码私钥数组成功");
        return pkcs1PrivateKey;
    }

    public static String convertToPkcs8Pem(PrivateKey privateKey) {
        log.info("私钥转换成 PKCS#8 格式的 PEM 字串");
        if (privateKey == null) {
            log.error("私钥不能为空");
            throw new UtilException("私钥不能为空");
        }
        byte[] data = privateKey.getEncoded();
        String pemPrivateKey = write2Pem("PRIVATE KEY", data);
        log.info("私钥转换成 PKCS#8 格式的 PEM 字串成功");
        return pemPrivateKey;
    }

    public static String convertToPkcs8Pem(PublicKey publicKey) {
        log.info("公钥转换成 PKCS#8 格式的 PEM 字串");
        if (publicKey == null) {
            log.error("公钥不能为空");
            throw new UtilException("公钥不能为空");
        }
        byte[] data = publicKey.getEncoded();
        String pemPublicKey = write2Pem("PRIVATE KEY", data);
        log.info("公钥转换成 PKCS#8 格式的 PEM 字串成功");
        return pemPublicKey;
    }

    public static String write2Pem(String type, byte[] data) {
        assert data != null;
        PemObject pemObject = new PemObject(type, data);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        try {
            pemWriter.writeObject(pemObject);
        } catch (IOException e) {
            log.error("转换成 PKCS1 格式失败", e);
            throw new UtilException("转换成 PKCS1 格式失败", e);
        } finally {
            try {
                pemWriter.close();
            } catch (IOException e) {
                log.error("关闭流失败", e);
            }
        }
        return stringWriter.toString();
    }

    public static byte[] read2Pem(String pem) {
        PemReader pemReader = null;
        PemObject pemObject;
        try {
            StringReader reader = new StringReader(pem);
            pemReader = new PemReader(reader);
            pemObject = pemReader.readPemObject();
        } catch (IOException e) {
            log.error("获取 PEM 失败", e);
            throw new UtilException("获取 PEM 失败", e);
        } finally {
            if (pemReader != null) {
                try {
                    pemReader.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
        return pemObject.getContent();
    }
}

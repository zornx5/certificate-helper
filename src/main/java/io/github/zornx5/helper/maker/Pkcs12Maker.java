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

package io.github.zornx5.helper.maker;

import io.github.zornx5.helper.exception.MakerException;
import io.github.zornx5.helper.util.CertificateUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * PKCS12 制作器
 *
 * @author zornx5
 */
@Slf4j
@Data
public class Pkcs12Maker {

    public static final String TYPE = "PKCS12";

    public String alias;

    public Pkcs12Maker() {
        alias = "User Key";
    }

    /**
     * 制作 PKCS12
     *
     * @param privateKey 用户私钥
     * @param chain      X509证书数组, 第一个（index 0）为 privateKey 对应的证书，index i+1 是 index i 的CA证书
     * @param password   口令
     * @return PKCS#12 {@link KeyStore}
     * @throws MakerException 没有提供者异常
     */
    public KeyStore makePkcs12(PrivateKey privateKey, X509Certificate[] chain, char[] password) throws MakerException {
        KeyStore keyStore;
        try {
            log.info("开始制作 PKCS12 KeySore 证书");
            keyStore = CertificateUtil.getKeyStore();
            keyStore.load(null, password);
            keyStore.setKeyEntry(alias, privateKey, password, chain);
        } catch (KeyStoreException e) {
            log.error("KeyStore 异常", e);
            throw new MakerException("KeyStore 异常", e);
        } catch (IOException e) {
            log.error("读取异常", e);
            throw new MakerException("读取异常", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("算法不支持异常", e);
            throw new MakerException("算法不支持异常", e);
        } catch (CertificateException e) {
            log.error("证书异常", e);
            throw new MakerException("证书异常", e);
        }
        log.info("制作 PKCS12 KeySore 证书完成");
        return keyStore;
    }

    /**
     * 制作 PKCS12
     *
     * @param privateKey 用户私钥
     * @param cert       X509证书
     * @param password   口令
     * @return the PKCS12 keystore
     * @throws MakerException 没有提供者异常
     */
    public KeyStore makePkcs12(PrivateKey privateKey, X509Certificate cert, char[] password) throws MakerException {
        return makePkcs12(privateKey, new X509Certificate[]{cert}, password);
    }
}

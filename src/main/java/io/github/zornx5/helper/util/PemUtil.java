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

import io.github.zornx5.helper.anntation.Beta;
import io.github.zornx5.helper.constant.HelperConstant;
import io.github.zornx5.helper.exception.UtilException;
import io.github.zornx5.helper.key.KeyHelperManager;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * PEM (Privacy Enhanced Mail) 工具类 <br>
 * PEM 一般为文本格式，以 -----BEGIN... 开头，以 -----END... 结尾，中间的内容是 Base64 编码,
 * 这种格式可以保存证书和私钥，有时我们也把 PEM 格式的私钥的后缀改为 .key 以区别证书与私钥。
 *
 * @author zornx5
 */
public class PemUtil {

    public static final String PRIVATE_KEY = "PRIVATE KEY";
    public static final String EC_PRIVATE_KEY = "EC PRIVATE KEY";
    public static final String EC_PUBLIC_KEY = "EC PUBLIC KEY";
    public static final String PUBLIC_KEY = "PUBLIC KEY";
    public static final String CERTIFICATE = "CERTIFICATE";
    public static final String PREFIX = "-----";

    public static byte[] readPemOrBase64Content(String pem) {
        if (StringUtil.isBlank(pem)) {
            return new byte[0];
        }
        pem = pem.trim();
        if (pem.startsWith(PREFIX) && pem.endsWith(PREFIX)) {
            PemReader pemReader = null;
            PemObject pemObject;
            try {
                StringReader reader = new StringReader(pem);
                pemReader = new PemReader(reader);
                pemObject = pemReader.readPemObject();
            } catch (IOException e) {
                throw new UtilException("获取 PEM 失败", e);
            } finally {
                IoUtil.close(pemReader);
            }
            return pemObject.getContent();
        } else {
            return Base64Util.decode2byte(pem);
        }
    }

    public static String writePemString(String type, byte[] data) throws UtilException {
        if (StringUtil.isBlank(type)) {
            throw new UtilException("类型不能为空");
        }
        if (Objects.isNull(data) || data.length == 0) {
            throw new UtilException(type + " 数据不能为空");
        }
        PemObject pemObject = new PemObject(type, data);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        try {
            pemWriter.writeObject(pemObject);
        } catch (IOException e) {
            throw new UtilException("转换成 PKCS1 格式失败", e);
        } finally {
            IoUtil.close(pemWriter);
        }
        return stringWriter.toString();
    }

    /**
     * 读取 PEM 格式的私钥
     *
     * @param pemStream PEM 流
     * @return {@link PrivateKey}
     */
    public static PrivateKey readPemPrivateKey(InputStream pemStream) {
        return (PrivateKey) readPemKey(pemStream);
    }

    /**
     * 读取 OpenSSL 生成的 ANS1 格式的 PEM 私钥文件，必须为 PKCS#1 格式
     *
     * @param keyStream 私钥 PEM 流
     * @return {@link PrivateKey}
     */
    @Beta
    public static PrivateKey readSm2PemPrivateKey(InputStream keyStream) {
        try {
            return KeyHelperManager.getByName(HelperConstant.SM2_ALGORITHM).convertPrivateKeyPkcs1ToPkcs8(readPem(keyStream));
        } finally {
            IoUtil.close(keyStream);
        }
    }

    /**
     * 读取 PEM 格式的公钥
     *
     * @param pemStream PEM 流
     * @return {@link PublicKey}
     */
    public static PublicKey readPemPublicKey(InputStream pemStream) {
        return (PublicKey) readPemKey(pemStream);
    }

    /**
     * 从 PEM 文件中读取公钥或私钥 <br>
     * 根据类型返回 {@link PublicKey} 或者 {@link PrivateKey}
     *
     * @param keyStream PEM 流
     * @return {@link Key}，null 表示无法识别的密钥类型
     */
    @Beta
    public static Key readPemKey(InputStream keyStream) {
        final PemObject object = readPemObject(keyStream);
        final String type = object.getType();
        if (StringUtil.isNotBlank(type)) {
            // private
            if (type.endsWith(EC_PRIVATE_KEY)) {
                return KeyHelperManager.getByName(HelperConstant.EC_ALGORITHM).convertToPrivateKey(object.getContent());
            }
            if (type.endsWith(PRIVATE_KEY)) {
                return KeyHelperManager.getByName(HelperConstant.RSA_ALGORITHM).convertToPrivateKey(object.getContent());
            }

            // public
            if (type.endsWith(EC_PUBLIC_KEY)) {
                return KeyHelperManager.getByName(HelperConstant.EC_ALGORITHM).convertToPublicKey(object.getContent());
            } else if (type.endsWith(PUBLIC_KEY)) {
                return KeyHelperManager.getByName(HelperConstant.RSA_ALGORITHM).convertToPublicKey(object.getContent());
            } else if (type.endsWith(CERTIFICATE)) {
                // TODO 从证书获取公钥
            }
        }
        throw new UtilException("无法识别的密钥类型");
    }

    /**
     * 从 PEM 流中读取公钥或私钥
     *
     * @param keyStream PEM 流
     * @return 密钥bytes
     * @since 5.1.6
     */
    public static byte[] readPem(InputStream keyStream) {
        PemObject pemObject = readPemObject(keyStream);
        if (null != pemObject) {
            return pemObject.getContent();
        }
        return null;
    }

    /**
     * 读取 PEM 文件中的信息，包括类型、头信息和密钥内容
     *
     * @param keyStream PEM 流
     * @return {@link PemObject}
     * @since 4.5.2
     */
    public static PemObject readPemObject(InputStream keyStream) {
        try {
            return readPemObject(new InputStreamReader(keyStream, HelperConstant.DEFAULT_CHARSET));
        } catch (UnsupportedEncodingException e) {
            throw new UtilException(e);
        }
    }

    /**
     * 读取 PEM 文件中的信息，包括类型、头信息和密钥内容
     *
     * @param reader PEM  Reader
     * @return {@link PemObject}
     * @since 5.1.6
     */
    public static PemObject readPemObject(Reader reader) {
        PemReader pemReader = null;
        try {
            pemReader = new PemReader(reader);
            return pemReader.readPemObject();
        } catch (IOException e) {
            throw new UtilException(e);
        } finally {
            IoUtil.close(pemReader);
        }
    }

    /**
     * 将私钥或公钥转换为 PEM 格式的字符串
     *
     * @param type    密钥类型（私钥、公钥、证书）
     * @param content 密钥内容
     * @return PEM 内容
     * @since 5.5.9
     */
    public static String toPem(String type, byte[] content) {
        final StringWriter stringWriter = new StringWriter();
        writePemObject(type, content, stringWriter);
        return stringWriter.toString();
    }

    /**
     * 写出 PEM 密钥（私钥、公钥、证书）
     *
     * @param type      密钥类型（私钥、公钥、证书）
     * @param content   密钥内容，需为PKCS#1格式
     * @param keyStream PEM 流
     * @since 5.1.6
     */
    public static void writePemObject(String type, byte[] content, OutputStream keyStream) {
        writePemObject(new PemObject(type, content), keyStream);
    }

    /**
     * 写出 PEM 密钥（私钥、公钥、证书）
     *
     * @param type    密钥类型（私钥、公钥、证书）
     * @param content 密钥内容，需为PKCS#1格式
     * @param writer  PEM Writer
     * @since 5.5.9
     */
    public static void writePemObject(String type, byte[] content, Writer writer) {
        writePemObject(new PemObject(type, content), writer);
    }

    /**
     * 写出 PEM 密钥（私钥、公钥、证书）
     *
     * @param pemObject PEM 对象，包括密钥和密钥类型等信息
     * @param keyStream PEM 流
     * @since 5.1.6
     */
    public static void writePemObject(PemObjectGenerator pemObject, OutputStream keyStream) {
        writePemObject(pemObject, new OutputStreamWriter(keyStream));
    }

    /**
     * 写出 PEM 密钥（私钥、公钥、证书）
     *
     * @param pemObject PEM 对象，包括密钥和密钥类型等信息
     * @param writer    PEM Writer
     * @since 5.5.9
     */
    public static void writePemObject(PemObjectGenerator pemObject, Writer writer) {
        final PemWriter pemWriter = new PemWriter(writer);
        try {
            pemWriter.writeObject(pemObject);
        } catch (IOException e) {
            throw new UtilException(e);
        } finally {
            IoUtil.close(pemWriter);
        }
    }
}

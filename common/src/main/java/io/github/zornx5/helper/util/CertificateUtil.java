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

import io.github.zornx5.helper.exception.UtilException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.util.Iterator;
import java.util.Map;

/**
 * 证书工具类
 *
 * @author zornx5
 */
public class CertificateUtil {

    /**
     * 构建 {@link X500Name}<br>
     * names 的 key 值必须是 {@link org.bouncycastle.asn1.x500.style.BCStyle#DefaultLookUp} 中存在的值（大小写不敏感）
     *
     * @param names 名称 map
     * @return {@link X500Name}
     * @throws UtilException 工具类异常
     */
    public static X500Name buildX500Name(Map<String, String> names) throws UtilException {
        if (names == null || names.size() == 0) {
            throw new UtilException("names can not be empty");
        }
        try {
            X500NameBuilder builder = new X500NameBuilder();
            Iterator<Map.Entry<String, String>> itr = names.entrySet().iterator();
            BCStyle x500NameStyle = (BCStyle) BCStyle.INSTANCE;
            while (itr.hasNext()) {
                Map.Entry<String, String> entry = itr.next();
                ASN1ObjectIdentifier oid = x500NameStyle.attrNameToOID(entry.getKey());
                builder.addRDN(oid, entry.getValue());
            }
            return builder.build();
        } catch (Exception e) {
            throw new UtilException(e.getMessage(), e);
        }
    }
}

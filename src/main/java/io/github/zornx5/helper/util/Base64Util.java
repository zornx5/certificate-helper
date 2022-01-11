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

import io.github.zornx5.helper.constant.IHelperConstant;
import io.github.zornx5.helper.exception.UtilException;
import lombok.extern.slf4j.Slf4j;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

/**
 * Base64 编解码工具类
 *
 * @author zornx5
 */
@Slf4j
public class Base64Util {
    public static String encode2String(byte[] data) {
        return encode2String(data, null);
    }

    public static String encode2String(byte[] data, String charset) {
        if (StringUtil.isBlank(charset)) {
            charset = IHelperConstant.DEFAULT_CHARSET;
        }
        try {
            return new String(Base64.getEncoder().encode(data), charset);
        } catch (UnsupportedEncodingException e) {
            log.error("Base64 编码失败", e);
            throw new UtilException("Base64 编码失败", e);
        }
    }

    public static byte[] decode2byte(String base64String) {
        return decode2byte(base64String, null);
    }

    public static byte[] decode2byte(String base64String, String charset) {
        if (StringUtil.isBlank(charset)) {
            charset = IHelperConstant.DEFAULT_CHARSET;
        }
        try {
            return Base64.getDecoder().decode(base64String.getBytes(charset));
        } catch (UnsupportedEncodingException e) {
            log.error("Base64 解码失败", e);
            throw new UtilException("Base64 解码失败", e);
        }
    }
}

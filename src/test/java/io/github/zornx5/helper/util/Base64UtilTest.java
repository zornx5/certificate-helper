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
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Base64Util.class})
public class Base64UtilTest {

    @Test
    public void encodeAndDecode() {
        String string = Base64Util.encode2String("abc".getBytes(StandardCharsets.UTF_8));
        Assert.assertNotNull(string);
        byte[] bytes = Base64Util.decode2byte(string);
        Assert.assertNotNull(bytes);
    }

    @Test(expected = UtilException.class)
    public void encodeError() {
        Base64Util.encode2String("abc".getBytes(StandardCharsets.UTF_8),"UnsupportedEncoding");
    }

    @Test(expected = UtilException.class)
    public void decodeError() {
        Base64Util.decode2byte("abc","UnsupportedEncoding");
    }
}

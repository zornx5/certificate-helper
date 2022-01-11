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

package io.github.zornx5.helper.exception;

import org.junit.Assert;
import org.junit.Test;

public class UtilExceptionTest {

    @Test
    public void testWork() {
        UtilException utilException = new UtilException();
        Assert.assertTrue(utilException instanceof CertificateHelperException);

        UtilException utilException1 = new UtilException("测试");
        Assert.assertEquals(utilException1.getMessage(), "测试");

        UtilException utilException2 = new UtilException("测试1", new UtilException());
        Assert.assertEquals(utilException2.getMessage(), "测试1");
        Assert.assertTrue(utilException2.getCause() instanceof UtilException);

        UtilException utilException3 = new UtilException(new KeyHelperException());
        Assert.assertTrue(utilException3.getCause() instanceof KeyHelperException);
    }

}

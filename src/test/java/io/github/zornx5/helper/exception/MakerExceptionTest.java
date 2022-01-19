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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MakerExceptionTest {

    @Test
    public void testWork() {
        MakerException utilException = new MakerException();
        Assertions.assertTrue(utilException instanceof CertificateHelperException);

        MakerException utilException1 = new MakerException("测试");
        Assertions.assertEquals(utilException1.getMessage(), "测试");

        MakerException utilException2 = new MakerException("测试1", new MakerException());
        Assertions.assertEquals(utilException2.getMessage(), "测试1");
        Assertions.assertTrue(utilException2.getCause() instanceof MakerException);

        MakerException utilException3 = new MakerException(new KeyHelperException());
        Assertions.assertTrue(utilException3.getCause() instanceof KeyHelperException);
    }

}

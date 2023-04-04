package io.github.zornx5.helper.util;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

@Slf4j
class IoUtilTest {

    @Test
    void close() {
        Assertions.assertDoesNotThrow(() -> {
            IoUtil.close(() -> {
                throw new UnsupportedOperationException();
            });
        });
    }
}

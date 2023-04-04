package io.github.zornx5.helper.anntation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注可能会取消或者未经测试完全的注解，标识调用者谨慎使用
 *
 * @author zornx5
 */
@Retention(RetentionPolicy.CLASS)
@Target({
        ElementType.ANNOTATION_TYPE,
        ElementType.CONSTRUCTOR,
        ElementType.FIELD,
        ElementType.METHOD,
        ElementType.TYPE
})
public @interface Beta {
}

<p align="center">
    <strong>一个简单的证书帮助工具</strong>
</p>

<p align="center">
    <a target="_blank" href="https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html">
        <img src="https://img.shields.io/badge/JDK-8+-green.svg" alt="JDK"/>
    </a>
    <a target="_blank" href="https://github.com/zornx5/certificate-helper">
        <img src="https://github.com/zornx5/certificate-helper/actions/workflows/gradle.yml/badge.svg" alt="build actions"/>
    </a>
    <a href="https://www.codacy.com/gh/zornx5/certificate-helper/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=zornx5/certificate-helper&amp;utm_campaign=Badge_Grade">
        <img src="https://app.codacy.com/project/badge/Grade/88a8612afc1440c992d0c8a0f0666a07" alt="code quality"/>
    </a>
    <a href="https://codecov.io/gh/zornx5/certificate-helper">
        <img src="https://codecov.io/gh/zornx5/certificate-helper/branch/main/graph/badge.svg?token=D1ERZRC4Z2" alt="code coverage"/>
    </a>
</p>

-------------------------------------------------------------------------------

[**English Documentation**](README-EN.md)

-------------------------------------------------------------------------------

## 简介

一个简单的证书帮助工具

## 安装

### Maven

在项目的 `pom.xml` 的 `dependencies` 中加入以下内容:

```xml

<dependency>
    <groupId>io.github.zornx5</groupId>
    <artifactId>certificate-helper</artifactId>
    <version>0.0.1</version>
</dependency>
```

### Gradle

```gradle
implementation 'io.github.zornx5:certificate-helper:0.0.1'
```

### 编译安装

访问主页：[https://github.com/zornx5/certificate-helper](https://github.com/zornx5/certificate-helper) 下载整个项目源码，然后执行:

```sh
./install.sh
```

然后就可以使用 `Maven` 引入了。
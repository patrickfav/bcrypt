# Bcrypt

This is an implementation the OpenBSD Blowfish password hashing algorithm, as described in "[A Future-Adaptable Password Scheme](http://www.openbsd.org/papers/bcrypt-paper.ps)" by Niels Provos and David Mazieres. It's core is based upon [jBcrypt](https://github.com/jeremyh/jBCrypt) heavily refactored, modernized and with a lot of updates and enhancements. It supports all common [versions](https://en.wikipedia.org/wiki/Bcrypt#Versioning_history), has a security sensitive API and is fully tested against a range of test vectors.

[![Download](https://api.bintray.com/packages/patrickfav/maven/bcrypt/images/download.svg)](https://bintray.com/patrickfav/maven/bcrypt/_latestVersion)
[![Build Status](https://travis-ci.org/patrickfav/bcrypt.svg?branch=master)](https://travis-ci.org/patrickfav/bcrypt)
[![Javadocs](https://www.javadoc.io/badge/at.favre.lib/bcrypt.svg)](https://www.javadoc.io/doc/at.favre.lib/bcrypt)
[![Coverage Status](https://coveralls.io/repos/github/patrickfav/bcrypt/badge.svg?branch=master)](https://coveralls.io/github/patrickfav/bcrypt?branch=master)

The code is compiled with [Java 7](https://en.wikipedia.org/wiki/Java_version_history#Java_SE_7) to be compatible with most [_Android_](https://www.android.com/) versions as well as normal Java applications.

## Quickstart

Add dependency to your `pom.xml`:

    <dependency>
        <groupId>at.favre.lib</groupId>
        <artifactId>bcrypt</artifactId>
        <version>{latest-version}</version>
    </dependency>

A simple example:

```java
    String password = "1234";
    char[] bcryptChars = BCrypt.withDefaults().hashToChar(12, password.toCharArray());
    String bcryptHashString = new String(bcryptChars);
    // $2a$12$US00g/uMhoSBm.HiuieBjeMtoN69SN.GE25fCpldebzkryUyopws6
    ...
    BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), bcryptChars);
    // result.verified == true
```

### API Description

```java
tbd
```

## Download

The artifacts are deployed to [jcenter](https://bintray.com/bintray/jcenter) and [Maven Central](https://search.maven.org/).

### Maven

Add dependency to your `pom.xml`:

    <dependency>
        <groupId>at.favre.lib</groupId>
        <artifactId>bcrypt</artifactId>
        <version>{latest-version}</version>
    </dependency>

### Gradle

Add to your `build.gradle` module dependencies:

    compile group: 'at.favre.lib', name: 'bcrypt', version: '{latest-version}'

### Local Jar

[Grab jar from latest release.](https://github.com/patrickfav/bcrypt/releases/latest)


## Description

### Enhancements over jBcrypt

* Optimized and fixed implementation (e.g. uses `StringBuilder` instead of `StringBuffer`)
* Support of most [version](https://en.wikipedia.org/wiki/Bcrypt#Versioning_history) variations (`$2a$`, `$2b$`, `$2x$`, `$2y$`) 
* Only uses byte and char arrays which can be wiped after use
* Provide your own salt
* Provide your own `SecureRandom` for salt generation
* Clearer and easier API
* Signed Jar and signed commits
* More tests (and probably higher coverage)

## Digital Signatures

### Signed Jar

The provided JARs in the Github release page are signed with my private key:

    CN=Patrick Favre-Bulle, OU=Private, O=PF Github Open Source, L=Vienna, ST=Vienna, C=AT
    Validity: Thu Sep 07 16:40:57 SGT 2017 to: Fri Feb 10 16:40:57 SGT 2034
    SHA1: 06:DE:F2:C5:F7:BC:0C:11:ED:35:E2:0F:B1:9F:78:99:0F:BE:43:C4
    SHA256: 2B:65:33:B0:1C:0D:2A:69:4E:2D:53:8F:29:D5:6C:D6:87:AF:06:42:1F:1A:EE:B3:3C:E0:6D:0B:65:A1:AA:88

Use the jarsigner tool (found in your `$JAVA_HOME/bin` folder) folder to verify.

### Signed Commits

All tags and commits by me are signed with git with my private key:

    GPG key ID: 4FDF85343912A3AB
    Fingerprint: 2FB392FB05158589B767960C4FDF85343912A3AB

## Build

### Jar Sign

If you want to jar sign you need to provide a file `keystore.jks` in the
root folder with the correct credentials set in environment variables (
`OPENSOURCE_PROJECTS_KS_PW` and `OPENSOURCE_PROJECTS_KEY_PW`); alias is
set as `pfopensource`.

If you want to skip jar signing just change the skip configuration in the
`pom.xml` jar sign plugin to true:

    <skip>true</skip>

### Build with Maven

Use maven (3.1+) to create a jar including all dependencies

    mvn clean install

## Tech Stack

* Java 7
* Maven

## BCrypt Implementations in Java

* [jBcrypt](https://github.com/jeremyh/jBCrypt) - the below implementations are based on jBcrypt
** [Spring Bcrypt](https://docs.spring.io/spring-security/site/docs/4.2.5.RELEASE/apidocs/org/springframework/security/crypto/bcrypt/BCrypt.html)
** [Apache Ldap](https://directory.apache.org/api/gen-docs/latest/apidocs/org/apache/directory/api/ldap/model/password/BCrypt.html)
* [Bouncy Castle](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/generators/BCrypt.java)
* 

# License

Copyright 2018 Patrick Favre-Bulle

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

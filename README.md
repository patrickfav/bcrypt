# Bcrypt

This is an implementation the OpenBSD Blowfish password hashing algorithm, as described in "[A Future-Adaptable Password Scheme](http://www.openbsd.org/papers/bcrypt-paper.ps)" by Niels Provos and David Mazieres. It's core is based upon [jBcrypt](https://github.com/jeremyh/jBCrypt), but  heavily refactored, modernized and with a lot of updates and enhancements. It supports all common [versions](https://en.wikipedia.org/wiki/Bcrypt#Versioning_history), has a security sensitive API and is fully tested against a range of test vectors and reference implementations.

[![Download](https://api.bintray.com/packages/patrickfav/maven/bcrypt/images/download.svg)](https://bintray.com/patrickfav/maven/bcrypt/_latestVersion)
[![Build Status](https://travis-ci.org/patrickfav/bcrypt.svg?branch=master)](https://travis-ci.org/patrickfav/bcrypt)
[![Javadocs](https://www.javadoc.io/badge/at.favre.lib/bcrypt.svg)](https://www.javadoc.io/doc/at.favre.lib/bcrypt)
[![Coverage Status](https://coveralls.io/repos/github/patrickfav/bcrypt/badge.svg?branch=master)](https://coveralls.io/github/patrickfav/bcrypt?branch=master)

The code is compiled with target [Java 7](https://en.wikipedia.org/wiki/Java_version_history#Java_SE_7) to be compatible with most [_Android_](https://www.android.com/) versions as well as normal Java applications.

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
String bcryptHashString = BCrypt.withDefaults().hashToString(12, password.toCharArray());
// $2a$12$US00g/uMhoSBm.HiuieBjeMtoN69SN.GE25fCpldebzkryUyopws6
    ...
BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), bcryptHashString);
// result.verified == true
```

### API Description

In the following, the main features and use cases are explained.

### Bcrypt Versions
This implementation supports the various versions, which basically only differ through their identifier:

```java
char[] bcryptChars = BCrypt.with(BCrypt.Version.VERSION_2Y).hashToChar(6, password.toCharArray());
// $2y$06$doGnefu9cbLkJTn8sef7U.dynHJFe5hS6xp7vLWb2Zu7e8cOuMVmS

char[] bcryptChars = BCrypt.with(BCrypt.Version.VERSION_2B).hashToChar(6, password.toCharArray());
// $2b$06$GskjDDM9oejRN8pxNhiSZuIw/cnjbsNb8IfWGd3TFQXtRfKTN95r.
```

By using `BCrypt.withDefaults()` it will default to version `$2a$`. The older `$2$` version is not supported.
For advanced use cases you may add your own version by providing a version identifier and a custom message formatter 
as well as parser.

```java
Version customVersion2f = new Version(new byte[]{0x32, 0x66} /* 2f */, myCustomFormatter, myCustomParser);
```

### byte[] vs char[] API

You can use either `char[]` or `byte[]` as input or output parameter. The reason `String` is usually omitted in security
relevant APIs is, that a primitive array can usually be overwritten, as to discard it immediately after use. It is however 
not possible to wipe the content of the immutable `String`. The encoding always defaults to `UTF-8`.

```java
byte[] bcryptHashBytes = BCrypt.withDefaults().hash(6, password.getBytes(StandardCharsets.UTF_8));
    ...
BCrypt.Result result = BCrypt.verifyer().verify(password.getBytes(StandardCharsets.UTF_8), bcryptHashBytes);
```

### Strict Verification

If you want the hash verification to only verify for a specific version you can use `verifyStrict()`

```java
byte[] hash2y =  BCrypt.with(BCrypt.Version.VERSION_2Y).hash(6, password.getBytes(StandardCharsets.UTF_8));
BCrypt.Result resultStrict = BCrypt.verifyer().verifyStrict(password.getBytes(StandardCharsets.UTF_8), hash2y, BCrypt.Version.VERSION_2A);
// resultStrict.verified == false
```

### Handling for Overlong passwords

Due to the limitation in the Blowfish cipher, the maximum password length is 72 bytes (note that UTF-8 encoded, a 
character can be as much as 4 bytes). Including the null-terminator byte, this will be reduced to 71 bytes. Per 
default, the `hash()` method will throw an exception if the provided password is too long. 

The API supports passing a custom handling in that case, to mimic the behaviour of some popular implementations to just
truncate the password.

```java
BCrypt.with(LongPasswordStrategies.truncate()).hash(6, new byte[100]);
BCrypt.with(LongPasswordStrategies.hashSha512()).hash(6, new byte[100]); //allows to honour all pw bytes
```

The password will only be transformed if it is longer than 71 bytes. *It is important to note, however, that using any
of these techniques will essentially create a custom flavor of Bcrypt, possibly not compatible with other implementations.*

### Custom Salt or SecureRandom
 
The caller may provide their own salt (which must be exactly 16 bytes) with:
 
```java
BCrypt.withDefaults().hash(6, salt16Bytes, password.getBytes(StandardCharsets.UTF_8));
```

or provide a custom instance of CPRNG which is used for the internal secure creation of the salt if none is passed:

```java
BCrypt.with(new SecureRandom()).hash(6, password.getBytes(StandardCharsets.UTF_8));
```

### Retrieve and Verify the Raw Hash

Per default the result of `hash()` methods will return in the [Modular Crypt Format](https://passlib.readthedocs.io/en/stable/modular_crypt_format.html)
(e.g. `$2y$06$doGnefu9cbLkJTn8sef7U.dynHJFe5hS6xp7vLWb2Zu7e8cOuMVmS`), but if you prefer encoding the hash yourself you can just use

```java
BCrypt.HashData hashData = BCrypt.withDefaults().hashRaw(6, salt, password.getBytes(StandardCharsets.UTF_8));
```

there is even a verify method optimized for this use-case:

```java
BCrypt.Result result = BCrypt.verifyer().verify(pw, hashData);
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

### Performance

Compared to 2 other implementations in Java they all compare pretty well. Using the simple micro benchmark in this repo
(see `BcryptMicroBenchmark`), I got the following results with a Intel Core i7-7700K, Win 10, Java 8 (172):


|              | cost 10  | cost 12   |
|--------------|----------|-----------|
| favreBcrypt  | 54.53 ms | 217.22 ms |
| jBcrypt      | 53.24 ms | 213.42 ms |
| BouncyCastle | 50.27 ms | 202.67 ms |

So it makes sense that mine and jBcrypt is pretty the same performance as it is the same core
implementation. Bouncy Castle is _slightly_ faster, but keep in mind that they do a little less work (only generating the hash, not the whole out message).

Compared to some other benchmarks, [like this one in node.js](https://github.com/dcodeIO/bcrypt.js/wiki/Benchmark) where a hash is with cost 12 is between 300-400ms (but with a weaker CPU).

**Disclaimer:** Micro benchmarks are [usually a really bad way to measure performance](https://mrale.ph/blog/2012/12/15/microbenchmarks-fairy-tale.html). These numbers are only informal tests
and should not be used to derive any security relevant decisions.

### Test Vectors and Reference Implementations

This implementation is tested against the bcrypt implementation jBcrypt and Bouncy Castle. It includes test vectors
found in the test cases of bcrypt and [various](https://stackoverflow.com/a/12761326/774398) [places](http://openwall.info/wiki/john/sample-hashes) [on](http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c?rev=HEAD) the web.

### Enhancements over jBcrypt

The core of this implementation is based on the popular jBcrypt. Many things around if have been heavily refactored and various new
features and APIs have been added:

* Optimized and fixed implementation (e.g. uses `StringBuilder` instead of `StringBuffer`)
* Support of most [version](https://en.wikipedia.org/wiki/Bcrypt#Versioning_history) variations (`$2a$`, `$2b$`, `$2x$`, `$2y$`)
* Customizable handling for passwords over 72 bytes
* Only uses byte and char arrays which can be wiped after use
* Easily get the raw hash
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
  * [Spring Bcrypt](https://docs.spring.io/spring-security/site/docs/4.2.5.RELEASE/apidocs/org/springframework/security/crypto/bcrypt/BCrypt.html)
  * [Apache Ldap](https://directory.apache.org/api/gen-docs/latest/apidocs/org/apache/directory/api/ldap/model/password/BCrypt.html)
* [Bouncy Castle](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/generators/BCrypt.java)

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

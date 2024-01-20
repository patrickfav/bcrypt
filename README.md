# Bcrypt Java Library and CLI Tool

This is an implementation of the OpenBSD Blowfish password hashing algorithm, as described in "[A Future-Adaptable Password Scheme](http://www.openbsd.org/papers/bcrypt-paper.ps)" by Niels Provos and David Mazieres. It's core is based on [jBcrypt](https://github.com/djmdjm/jBCrypt), but  heavily refactored, modernized and with a lot of updates and enhancements. It supports all common [versions](https://en.wikipedia.org/wiki/Bcrypt#Versioning_history), has a security sensitive API and is fully tested against a range of test vectors and reference implementations.

[![Maven Central](https://img.shields.io/maven-central/v/at.favre.lib/bcrypt)](https://mvnrepository.com/artifact/at.favre.lib/bcrypt)
[![Github Actions](https://github.com/patrickfav/bcrypt/actions/workflows/build_deploy.yml/badge.svg)](https://github.com/patrickfav/bcrypt/actions)
[![Javadocs](https://www.javadoc.io/badge/at.favre.lib/bcrypt.svg)](https://www.javadoc.io/doc/at.favre.lib/bcrypt)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=patrickfav_bcrypt&metric=coverage)](https://sonarcloud.io/summary/new_code?id=patrickfav_bcrypt)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=patrickfav_bcrypt&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=patrickfav_bcrypt)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=patrickfav_bcrypt&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=patrickfav_bcrypt)

The code is compiled with target [Java 7](https://en.wikipedia.org/wiki/Java_version_history#Java_SE_7) to be compatible with most [_Android_](https://www.android.com/) versions as well as normal Java applications.

## Quickstart

This library is published to Maven Central

Add the dependency of the [latest version](https://github.com/patrickfav/bcrypt/releases/latest) to your `pom.xml`:

```xml
<dependency>
    <groupId>at.favre.lib</groupId>
    <artifactId>bcrypt</artifactId>
    <version>{latest-version}</version>
</dependency>
```

Or if you are using Gradle:

```groovy
implementation("at.favre.lib:bcrypt:{latest-version}")
```

A simple example:

```java
String password = "1234";
String bcryptHashString = BCrypt.withDefaults().hashToString(12, password.toCharArray());
// $2a$12$US00g/uMhoSBm.HiuieBjeMtoN69SN.GE25fCpldebzkryUyopws6
    ...
BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), bcryptHashString);
// result.verified == true
```

## API Description for the Java Library

The following APIs are for advanced use-cases and require the developer to be familiar with the material. If you are not
sure, just stick to the quick start example.

### Bcrypt Versions
This implementation supports the various versions, which basically only differ through their identifier:

```java
char[] bcryptChars = BCrypt.with(BCrypt.Version.VERSION_2Y).hashToChar(6, password.toCharArray());
// $2y$06$doGnefu9cbLkJTn8sef7U.dynHJFe5hS6xp7vLWb2Zu7e8cOuMVmS

char[] bcryptChars = BCrypt.with(BCrypt.Version.VERSION_2B).hashToChar(6, password.toCharArray());
// $2b$06$GskjDDM9oejRN8pxNhiSZuIw/cnjbsNb8IfWGd3TFQXtRfKTN95r.
```

For example the [PHP implementation of bcrypt](http://php.net/manual/en/function.password-hash.php) will return hashes with version `$2y$`.
By using `BCrypt.withDefaults()` it will default to version `$2a$`. The older `$2$` version is not supported.
For advanced use cases you may add your own version by providing a version identifier and a custom message formatter 
as well as parser.

```java
Version customVersion2f = new Version(new byte[]{0x32, 0x66} /* 2f */, true, true, myCustomFormatter, myCustomParser);
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

and

```java
char[] bcryptChars = BCrypt.withDefaults().hashToChar(12, password.toCharArray());
    ...
BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), bcryptChars);
```

Note, that there are APIs that return `String` type hash and can verify it directly. This is done
out of convenience and to present easy to understand API for all audiences. Usually the hash is 
not as critical as the raw password, so it might be ok to not be able to wipe it immediately. But 
usually you should prefer `char[]` or `byte[]` APIs.

### Strict Verification

If you want the hash verification to only verify for a specific version you can use `verifyStrict()`

```java
byte[] hash2y = BCrypt.with(BCrypt.Version.VERSION_2Y).hash(6, password.getBytes(StandardCharsets.UTF_8));
BCrypt.Result resultStrict = BCrypt.verifyer(BCrypt.Version.VERSION_2A).verifyStrict(password.getBytes(StandardCharsets.UTF_8), hash2y);
// resultStrict.verified == false
```

### Handling for Overlong passwords

Due to the limitation in the Blowfish cipher, the maximum password length is 72 bytes (note that UTF-8 encoded, a 
character can be as much as 4 bytes). Per 
default, the `hash()` method will throw an exception if the provided password is too long. 

The API supports passing a custom handling in that case, to mimic the behaviour of some popular implementations to just
truncate the password.

```java
BCrypt.with(LongPasswordStrategies.truncate(Version.VERSION_2A)).hash(6, pw);
BCrypt.with(LongPasswordStrategies.hashSha512(Version.VERSION_2A)).hash(6, pw); //allows to honour all pw bytes
```

Don't forget to use the same strategy when verifying:

```java
BCrypt.verifyer(LongPasswordStrategies.truncate(Version.VERSION_2A)).verify(pw, hash);
```

The password will only be transformed if it is longer than 72 bytes. *It is important to note, however, that using any
of these techniques will essentially create a custom flavor of Bcrypt, possibly not compatible with other implementations.*

However, you can also disable this warning by using the `LongPasswordStrategies.none` strategy. It will pass the raw data to the internal cryptographic primitive (which in turn will ignore anything longer than 72 bytes). This is the standard behaviour of BCrypt.

### Custom Salt or SecureRandom
 
The caller may provide their own salt (which must be exactly 16 bytes) with:
 
```java
BCrypt.withDefaults().hash(6, salt16Bytes, password.getBytes(StandardCharsets.UTF_8));
```

or provide a custom instance of a cryptographically secure pseudorandom number generator ([CPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator)) 
which is used for the internal secure creation of the salt if none is passed:

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

You could even use the default formatter later on:

```java
byet[] hashMsg = Version.VERSION_2A.formatter.createHashMessage(hashData);
```

## Command Line Interface (CLI) Tool

In addition to the Java library there is a companion command line interface (CLI) tool (found in the `bcrypt-cli` 
sub-module) which uses this bcrypt library. It features creating bcrypt password hashes with chosen cost factor and 
optionally passed salt value as well as verifying given hash against given password.

This command will create a bcrypt hash:

    java -jar bcrypt-cli.jar 'mySecretPw' -b 12

This command will verify given bcrypt hash (returns `!= 0` if could not be verified):

    java -jar bcrypt-cli.jar 'mySecretPw' -c '$2a$08$hgaLWQl7PdKIkx9iQyoLkeuIqizWtPErpyC7aDBasi2Pav97wwW9G'

The full API can be read in the doc by passing `-h`

    -b,--bhash <cost> <[16-hex-byte-salt]>   Use this flag if you want to compute the bcrypt hash. Pass the
                                             logarithm cost factor (4-31) and optionally the used salt as hex
                                             encoded byte array (must be exactly 16 bytes/32 characters hex).
                                             Example: '--bhash 12 8e270d6129fd45f30a9b3fe44b4a8d9a'
    -c,--check <bcrypt-hash>                 Use this flag if you want to verify a hash against a given
                                             password. Example: '--check
                                             $2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'
    -h,--help                                Prints help docs.
    -v,--version                             Prints current version.

## Download

The artifacts are deployed to [Maven Central](https://search.maven.org/).

### Maven

Add the dependency of the [latest version](https://github.com/patrickfav/bcrypt/releases) to your `pom.xml`:

```xml
<dependency>
    <groupId>at.favre.lib</groupId>
    <artifactId>bcrypt</artifactId>
    <version>{latest-version}</version>
</dependency>
```

### Gradle

Add to your `build.gradle` module dependencies:

    implementation group: 'at.favre.lib', name: 'bcrypt', version: '{latest-version}'

### Local Jar Library

[Grab jar from latest release.](https://github.com/patrickfav/bcrypt/releases/latest)

### OSGi

The library should be prepared to be used with the OSGi framework with the help of the [bundle plugin](http://felix.apache.org/documentation/subprojects/apache-felix-maven-bundle-plugin-bnd.html).

### CLI Tool

Get the binary from the [release page](https://github.com/patrickfav/bcrypt/releases/latest) or build it yourself by with mvn (see below). The `jar`
will be in the `bcrypt-cli/target` folder.

## Description

### Security Analysis

I'll quote security expert [Thomas Pornin](http://www.bolet.org/~pornin/) on this (an excerpt [from this post](https://security.stackexchange.com/a/6415/60108)):

**tl;dr bcrypt is better than PBKDF2 because PBKDF2 can be better accelerated with GPUs. As such, PBKDF2 is easier to brute 
force offline with consumer hardware. [srcypt tried to address bcrypt's shortcommings, but didn't succeed all the way.](https://security.stackexchange.com/a/26253/60108) 
[Argon2 is too new to tell.](https://security.stackexchange.com/a/119784/60108)**

> Bcrypt has the best kind of repute that can be achieved for a cryptographic algorithm: it has been around for quite some time, used quite widely, "attracted attention", and yet remains unbroken to date.
>
>
> #### Why bcrypt is somewhat better than PBKDF2
>
> If you look at the situation in details, you can actually see some points where bcrypt is better than, say, PBKDF2. Bcrypt is a password hashing function which aims at being slow. To be precise, we want the password hashing function to be as slow as possible for the attacker while not being intolerably slow for the honest systems. (...)
> What we want to avoid is that an attacker might use some non-PC hardware which would allow him to suffer less than us from the extra work implied by bcrypt or PBKDF2. In particular, an industrious attacker may want to use a GPU or a FPGA. SHA-256, for instance, can be very efficiently implemented on a GPU, since it uses only 32-bit logic and arithmetic operations that GPU are very good at. (...)
> Bcrypt happens to heavily rely on accesses to a table which is constantly altered throughout the algorithm execution. This is very fast on a PC, much less so on a GPU, where memory is shared and all cores compete for control of the internal memory bus. Thus, the boost that an attacker can get from using GPU is quite reduced, compared to what the attacker gets with PBKDF2 or similar designs.
> 
>
> #### Why bcrypt is not optimally secure
>
> Bcrypt needs only 4 kB of fast RAM. While bcrypt does a decent job at making life difficult for a GPU-enhanced attacker, it does little against a FPGA-wielding attacker.
>
>
> #### What NIST recommends
>
> NIST has issued Special Publication SP 800-132 on the subject of storing hashed passwords. Basically they recommend PBKDF2. This does not mean that they deem bcrypt insecure; they say nothing at all about bcrypt. It just means that NIST deems PBKDF2 "secure enough" (and it certainly is much better than a simple hash !). Also, NIST is an administrative organization, so they are bound to just love anything which builds on already "Approved" algorithms like SHA-256. On the other hand, bcrypt comes from Blowfish which has never received any kind of NIST blessing (or curse).

#### What Cost Factor should I use?

Again, quote from Thomas Pornin [from this post](https://security.stackexchange.com/a/31846/60108):

> As much as possible! This salted-and-slow hashing is an arms race between the attacker and the defender. You use many iterations to make the hashing of a password harder for everybody. To improve security, you should set that number as high as you can tolerate on your server, given the tasks that your server must otherwise fulfill. Higher is better.

So find your tolerable slowest performance (for some this is 3 sec, for some 250 ms, for some 1 minute) and try it out on an average lower end device your user-base would use (if the client has to calculate the hash) and/or benchmark your server.

Note, that it is unfortunately [NOT possible to increase the cost-factor](https://security.stackexchange.com/a/23308/60108) 
of a calculated bcrypt hash without knowing the original password. A possible solution is to persist hashes with multiple work factors for
different use cases/migration.

### Performance

Compared to two other implementations in Java they all share similar performance characteristics. Using the simple micro
 benchmark in this repo (see `BcryptMicroBenchmark`), I got the following results with a Intel Core [i7-7700K](https://ark.intel.com/products/97129/Intel-Core-i7-7700K-Processor-8M-Cache-up-to-4_50-GHz), Win 10, 
 Java 8 (172):

|              | cost 6   | cost   8  | cost 10  | cost 12   | cost 14   |
|--------------|----------|-----------|----------|-----------|-----------|
| favreBcrypt  |  3.38 ms |  13.54 ms | 53.91 ms | 216.01 ms | 873.93 ms |
| jBcrypt      |  3.43 ms |  13.75 ms | 54.76 ms | 218.62 ms | 883.55 ms |
| BouncyCastle |  3.14 ms |  12.5 ms  | 49.8 ms  | 199.09 ms | 799.71 ms |

compare that with a 2017 flag ship Android phone Samsung Galaxy S8+ ([SM-G955F](https://www.gsmarena.com/samsung_galaxy_s8+-8523.php)) with Android 8:

|              | cost 6   | cost   8  | cost 10   | cost 12   | cost 14   |
|--------------|----------|-----------|-----------|-----------|-----------|
| favreBcrypt  |  8.13 ms |  29.05 ms | 110.62 ms | 438.45 ms | 1768.44 ms|
| jBcrypt      |  7.91 ms |  30.91 ms | 116.45 ms | 462.93 ms | 1855.36 ms|
| BouncyCastle |  10.41 ms|  38.03 ms | 149.09 ms | 595.19 ms | 2383.72 ms|

More benchmarks can be found in the [wiki](https://github.com/patrickfav/bcrypt/wiki/Benchmark).

So it makes sense that this implementation and jBcrypt's has the same performance as it is the same core
implementation. Bouncy Castle is _slightly_ faster (on the JVM, not on Android interestingly), but keep in mind that they do a little less work (only generating the hash, not the whole out message).

Compare this to other benchmarks, [like this one in node.js](https://github.com/dcodeIO/bcrypt.js/wiki/Benchmark) where a bcrypt hash with cost factor 12 is between 300-400ms.

**Disclaimer:** Micro benchmarks are [usually a really bad way to measure performance](https://mrale.ph/blog/2012/12/15/microbenchmarks-fairy-tale.html). 
These numbers are only informal tests and should not be used to derive any security relevant decisions.

#### JMH Benchmark

Additionally there is JMH benchmark module, which is probably better than my home-brew micro benchmark. Build it with 
maven `./mvnw clean install` (you may want to disable jar signing with `<project.skipJarSign>` property) and execute
it with `java -jar modules/benchmark-jmh/target/benchmark-jmh-x.y.z-full.jar`.

### Test Vectors and Reference Implementations

This implementation is tested against the bcrypt implementation jBcrypt and Bouncy Castle. It includes test vectors
found in the test cases of bcrypt and [various](https://stackoverflow.com/a/12761326/774398) [places](http://openwall.info/wiki/john/sample-hashes) [on](http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c?rev=HEAD) [the web](https://github.com/BcryptNet/bcrypt.net/blob/main/src/BCrypt.Net.UnitTests/BCryptTests.cs). Additionally I [created a reference test suite](https://github.com/patrickfav/bcrypt/wiki/Published-Test-Vectors) for regression tests and to check compatibility with
other libraries.

### The Modular Crypt Format for bcrypt

Since bcrypt evolved from OpenBSD most implementations output the hash in the modular crypt format (MCF). In contrast to e.g. normal `sha` hash
it includes the used hash function, cost factor, salt and hash itself. This makes it specifically convenient for password storage use. Formally 
the [format](http://passlib.readthedocs.io/en/stable/modular_crypt_format.html) is:

> (...) a standard for encoding password hash strings, which requires hashes have the format `${identifier}${content}`; where `{identifier}` 
> is an short alphanumeric string uniquely identifying a particular scheme, and `{content}` is the contents of the scheme, using only the 
> characters in the regexp range `[a-zA-Z0-9./]`.

Analyzing the bcrypt format in detail we get:

     ${identifier}${cost-factor}${16-bytes-salt-radix64}{23-bytes-hash-radix64}
     
With bcrypt the version identifier was `$2$`, but unfortunately early implementations [did not define how to handle non-ASCII characters](http://undeadly.org/cgi?action=article&sid=20140224132743),
so to tag the old hashes, a new minor version was introduced which was not compatible with the earlier one: `$2a$`. 
This is the default version used by most implementations. There are other minor versions which are only used to tag various non-backwards 
compatible bugs in different implementations (namely `$2x$` and `$2y$` used by `crypt_blowfish` (PHP) and `$2b$` by OpenBSD). These are usually 
irrelevant for implementations that did not have these bugs, so there is no advantage in setting the version to e.g. `$2y$` apart from making 
it compatible with different systems. The actual format is the same as `$2a$`.

The cost factor is the logarithmic work factor value as defined (4-30) printed as normal ASCII characters `[0-9]`. After that the 16 byte salt 
encoded with a base64 dialect follows (22 characters) as well as the actual bcrypt hash (23 bytes / 31 characters encoded with the base64 dialect).

Here is a full example:

    $2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.

Here `$2a$` is the version, the cost factor is `8`, the salt is `cfcvVd2aQ8CMvoMpP2EBfe` and the bcrypt hash is `odLEkkFJ9umNEfPD18.hUF62qqlC/V.`.

The used encoding is similar to the RFC * base64 encoding schema, but [with different mappings](https://en.wikipedia.org/wiki/Base64#Radix-64_applications_not_compatible_with_Base64)
 (`./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` vs. `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`) 
 only used by OpenBSD. In the code base this encoding is usually referenced as "Radix64" (see `Radix64Encoder`). The usual padding with `=` is
 omitted.

### Enhancements over jBcrypt

The core of this implementation is based on the popular jBcrypt. Many things around if have been heavily refactored and various new
features and APIs have been added:

* Optimized and fixed implementation
* Support of most [version](https://en.wikipedia.org/wiki/Bcrypt#Versioning_history) variations (`$2a$`, `$2b$`, `$2x$`, `$2y$`) with support of custom versions
* Customizable handling for passwords over 72 bytes
* Only uses byte and char arrays which can be wiped after use
* Faster Radix64 implementation
* Allow a cost factor of 31 (jBcrypt only allows up to 30)
* Easily get the raw hash
* Provide your own salt or `SecureRandom` for salt generation
* Clearer and easier API
* Signed Jar and signed commits
* More tests (and probably higher coverage)

## Security Relevant Information

### OWASP Dependency Check

This project uses the [OWASP Dependency-Check](https://www.owasp.org/index.php/OWASP_Dependency_Check) which is a utility that identifies project dependencies and checks if there are any known, publicly disclosed, vulnerabilities against a [NIST database](https://nvd.nist.gov/vuln/data-feeds).
The build will fail if any issue is found.

### Digital Signatures

#### Signed Jar

The provided JARs in the Github release page are signed with my private key:

    CN=Patrick Favre-Bulle, OU=Private, O=PF Github Open Source, L=Vienna, ST=Vienna, C=AT
    Validity: Thu Sep 07 16:40:57 SGT 2017 to: Fri Feb 10 16:40:57 SGT 2034
    SHA1: 06:DE:F2:C5:F7:BC:0C:11:ED:35:E2:0F:B1:9F:78:99:0F:BE:43:C4
    SHA256: 2B:65:33:B0:1C:0D:2A:69:4E:2D:53:8F:29:D5:6C:D6:87:AF:06:42:1F:1A:EE:B3:3C:E0:6D:0B:65:A1:AA:88

Use the jarsigner tool (found in your `$JAVA_HOME/bin` folder) folder to verify.

#### Signed Commits

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

    <project.skipJarSign>true</project.skipJarSign>

### Build with Maven

Use the Maven wrapper to create a jar including all dependencies

    ./mvnw clean install

### Checkstyle Config File

This project uses my [`common-parent`](https://github.com/patrickfav/mvn-common-parent) which centralized a lot of
the plugin versions aswell as providing the checkstyle config rules. Specifically they are maintained in [`checkstyle-config`](https://github.com/patrickfav/checkstyle-config). Locally the files will be copied after you `mvnw install` into your `target` folder and is called
`target/checkstyle-checker.xml`. So if you use a plugin for your IDE, use this file as your local configuration.

## Tech Stack

* Java 7 Source, JDK 11 required to build (not yet JDK17 compatible)
* Maven 3

## Libraries & Credits

* [jBcrypt](https://github.com/djmdjm/jBCrypt) (derived the "Blowfish Expensive key setup") (under BSD licence)
* Radix64 implementation derived from [Square's Okio Base64](https://github.com/square/okio) (under Apache v2)
* [Bytes](https://github.com/patrickfav/bytes-java) (byte array utility library) (under Apache v2)


### BCrypt Implementations in Java

* [jBcrypt](https://github.com/djmdjm/jBCrypt) - the below implementations are based on jBcrypt
  * [Spring Bcrypt](https://docs.spring.io/spring-security/site/docs/4.2.5.RELEASE/apidocs/org/springframework/security/crypto/bcrypt/BCrypt.html)
  * [Apache Ldap](https://directory.apache.org/api/gen-docs/latest/apidocs/org/apache/directory/api/ldap/model/password/BCrypt.html)
  * [Tomcat Bcrypt](https://github.com/andreacomo/tomcat-bcrypt)
* [Bouncy Castle](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/generators/BCrypt.java)

## Further Reading

* [The Bcrypt Protocol… is kind of a mess](https://hackernoon.com/the-bcrypt-protocol-is-kind-of-a-mess-4aace5eb31bd)

## Related Libraries

* [Single Step KDF [NIST SP 800-56C] (Java)](https://github.com/patrickfav/singlestep-kdf)
* [HKDF [RFC5869] Two-Step KDF (Java)](https://github.com/patrickfav/hkdf)

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

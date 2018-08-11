-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-dontusemixedcaseclassnames
-dontobfuscate
-verbose

-keepattributes *Annotation*,EnclosingMethod, InnerClasses, Exceptions, Signature, SourceFile, LineNumberTable, MethodParameters
-renamesourcefileattribute SourceFile
-optimizationpasses 3
-overloadaggressively

-keepclasseswithmembernames class * {
    native <methods>;
}

-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

################################################

-dontnote com.sun.**
-dontwarn com.sun.**

-dontnote sun.**
-dontwarn sun.**

-dontnote java.**
-dontwarn java.**

-dontnote javax.**
-dontwarn javax.**

# keep all public classes in main package
-keep public class at.favre.lib.crypto.bcrypt.** { public *; }
-keep interface at.favre.lib.crypto.bcrypt.** { <methods>; }

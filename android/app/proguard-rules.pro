# The native library resolves these by name at JNI registration time; R8 has no way
# to see the reference and would strip them.
-keep class org.pactmesh.android.Native { *; }

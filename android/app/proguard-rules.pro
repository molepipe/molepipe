# Keep gomobile-generated Go bindings (JNI bridge)
-keep class org.golang.** { *; }
-keep class go.** { *; }

# Keep the ShellBridge JavaScript interface
-keep class org.molepipe.molepipe.MainActivity$ShellBridge { *; }

# Keep BackendService for service binding
-keep class org.molepipe.molepipe.BackendService { *; }

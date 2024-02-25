# Android Network Interception Case Study: Observing OkHttp Traffic without Bypassing Certificate Pinning

This project provides a case study demonstrating how to intercept the majority of OkHttp3 network traffic within an Android application without directly bypassing certificate pinning. The technique leverages Frida's dynamic instrumentation capabilities.

## Key Features

- Request/Response Inspection: Effortlessly view the contents of OkHttp3 requests and responses.
- Obfuscation Handling: Frida's capabilities allow circumventing common obfuscation techniques used to protect Android applications.
- Customization: The provided code serves as a modifiable template for you to tailor to your specific analysis needs.

## Prerequisites

- Rooted Android Device or Emulator: Frida often requires root access or a debuggable environment.
- Frida Installed: Refer to Frida's documentation for installation on your OS and Android device: https://frida.re/docs/installation/
- Basic Frida Knowledge: Understanding core Frida concepts (scripting, attaching, hooking) is beneficial.
- Android App (.apk): The obfuscated Android application you intend to analyze.


## Usage

1. Connect to Device: Establish an ADB connection to your Android device or emulator.

2. Install Frida Server: Download and install the appropriate Frida server version for your device's architecture.

3. Launch App: Start the target Android application on the device.

4. Run Frida Script: Modify script.js with any necessary adjustments for targeting specific OkHttp classes. Then execute the script:

```bash
frida -U -f [app.package.name] -l script.js --no-pause
```




Example script.js

```javaScript
Java.perform(function() {
    // Target OkHttp's relevant classes (adjust if obfuscated)
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    var Response = Java.use("okhttp3.Response");

    // Hook into OkHttp's call method
    OkHttpClient.newCall.overload("okhttp3.Request").implementation = function(request) {
        console.log("Request URL:", request.url().toString());
        console.log("Request Headers:", request.headers());
        // ... (add more logging or modifications)

        var result = this.newCall(request); 
        return result;
    };

    // Hook into OkHttp's response handling
    Response.body.implementation = function() {
        console.log("Response Body:", this.body().string());
        // ... (add more logging or modifications)

        var result = this.body();
        return result;
    };
});
```


### Important Notes

- App-Specific Adjustments: You will likely need to modify class names and method signatures in script.js if the target app uses obfuscation.
- Security Considerations: Be mindful of the security and ethical implications of intercepting network traffic from applications you don't own.
- Frida Power: Explore Frida's extensive capabilities for even more advanced instrumentation scenarios.


### Disclaimer

This project is intended for educational and research purposes only. Use responsibly.

Let me know if you'd like any further additions or specific usage examples!

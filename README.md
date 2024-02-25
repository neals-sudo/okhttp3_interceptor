# Android Network Interception Case Study: Observing OkHttp Traffic without Bypassing Certificate Pinning

This project provides a case study demonstrating how to intercept the majority of OkHttp3 network traffic within an Android application without directly bypassing certificate pinning. This technique leverages Frida's dynamic instrumentation capabilities.

## Key Features

- Request/Response Inspection: Effortlessly view the contents of OkHttp3 requests and responses.
- Obfuscation Handling: Frida's capabilities allow circumventing common obfuscation techniques used to protect Android applications.
- Customization: The provided code serves as a modifiable template for you to tailor to your specific analysis needs.

## Usage

**Prerequisites**

* Rooted Android device or emulator.
* Frida installed and configured on your system.
* Target Android application (.apk) installed on your device.

**Steps**

1. **Obtain App Package Name:** Find the package name (app ID) of your target Android app. You can often find this in the app's properties in the Play Store or using a tool like `adb shell pm list packages`.

2. **Start the Target App:** Launch the target application on your Android device.

3. **Run the `injector.js` Script:** Execute the following command in your terminal, replacing `com.example.app` with the actual package name you obtained:

   ```bash
   frida -U -f com.example.app -l injector.js --no-pause
   ```

### Important Notes

- Security Considerations: Be mindful of the security and ethical implications of intercepting network traffic from applications you don't own.
- Frida Power: Explore Frida's extensive capabilities for even more advanced instrumentation scenarios.


### Disclaimer

This project is intended for educational and research purposes only. Use responsibly.

Let me know if you'd like any further additions or specific usage examples!

### **Privacy Policy**

**Effective Date:** May 13, 2026

**Deadlight Proxy** ("we", "our", or "the App") is a lightweight, local proxy server application for Android. This Privacy Policy explains how the app handles data.

---

#### 1. Information We Collect

**We collect no personal data.**

- The app runs **entirely locally** on your device.
- No analytics, crash reporting, telemetry, or tracking libraries are used.
- No data is sent to our servers or any third parties by default.

#### 2. How the App Works

Deadlight Proxy acts as a **local proxy** (HTTP, SOCKS5, etc.) on your Android device:

- It listens on `127.0.0.1:8080` (or the port you configure).
- It forwards traffic **on your behalf** to the destinations you choose.
- **In this Android build:**
  - VPN mode is disabled
  - TLS/SSL interception (MITM) is disabled
  - Plugin system is limited / disabled
- All proxying happens in real time on your device.

#### 3. Permissions

The app may request the following permissions:

| Permission                  | Reason |
|----------------------------|--------|
| `FOREGROUND_SERVICE`       | To keep the proxy running reliably in the background |
| Internet / Network         | Required to function as a proxy |
| Notification               | To show connection status and control the service |

No other dangerous permissions are used.

#### 4. Local Data Storage

- Configuration files and logs are stored locally on your device.
- No data is uploaded to the cloud unless you explicitly configure federation or external services (not enabled in the default Android build).

#### 5. Third Parties

- The app itself does **not** integrate with any third-party analytics or advertising services.
- Any traffic you route through the proxy (e.g., through browsers or apps) is handled according to the privacy policies of those destination services — not by Deadlight Proxy.

#### 6. Open Source

Deadlight Proxy is open source. You can review the full source code here:  
**https://github.com/gnarzilla/deadlight-proxy**

#### 7. Children's Privacy

This app is not directed at children under 13 and does not knowingly collect data from them.

#### 8. Changes to This Policy

We may update this Privacy Policy occasionally. We will notify you of significant changes by updating the effective date and posting the new policy in the app or on our GitHub repository.

#### 9. Contact Us

If you have any questions about this Privacy Policy, please contact us at:  
**gnarzilla@deadlight.boo**

---

# SSG8 + Microsoft Edge: Website Protection

This is an **explicitly installed, removable Edge extension** paired to the native SSG8 app. It is not a Windows-wide firewall or proxy. SSG8 remains safe to close and does not need administrator permissions.

## What it does

- While Website Protection is **OFF**, the extension allows ordinary web browsing.
- Each HTTP(S) main-frame navigation attempt in Edge is reported **as hostname metadata only** to SSG8 on `127.0.0.1:48765`. Paths, query strings, fragments, passwords and request bodies are not sent.
- Those events are passed through `ProtectionManager.evaluate_website` and the existing autonomous controller. The internal suspicion score increases and can activate Website Protection automatically.
- When Website Protection is **ON**, Edge's extension redirects attempted HTTP(S) webpage navigation to an SSG8 access-denied page. **No website list is needed.** The block applies to Edge profiles where this extension was installed, not other browsers.
- Extension polling runs on startup and periodically (about every 30 seconds), and navigation attempts also request synchronization. A just-activated policy may take a moment to propagate. Existing loaded tabs are not forcibly closed.
- When SSG8 is offline, the extension automatically removes the redirect rule after its next status check. It can also be paused instantly via its toolbar popup or its blocked page.

**Limitations:** Doesn't block Edge's own `edge://` settings pages, other browsers or browsers profiles without the extension, non-web protocols, HTTP requests made by other programs, or every background network request. SSG8 needs to be running to record and score attempts. Website events captured from Edge may need live testing if Edge handles certain redirects differently.

## Installation on Windows VM

1. Launch SSG8 normally (no administrator permissions required). The app runs the local bridge automatically.
2. Open **Microsoft Edge**, navigate to `edge://extensions`, and turn on **Developer mode**.
3. Click **Load unpacked** and select the **`edge-extension` directory** containing `manifest.json`.
4. Keep SSG8 running. The extension popup should say **SSG8 is running** and initially **Website Protection is not yet active**.
5. Visit `https://example.com/` repeatedly or interact with other SSG8 features; the application automatically increases its internal security assessment, and Website Protection eventually activates. After the extension syncs, browsing to HTTP(S) sites should show the **SSG8 Access Denied** page.
6. Confirm the website evaluations appear in SSG8's **Security Logs** and the protection status is displayed correctly in the Dashboard.
7. Use the toolbar popup's **Pause website protection** button, or disable/remove the extension at `edge://extensions`, to restore browsing immediately. SSG8 also stops serving active policy when closed.

**Do not** use Windows Firewall rules, DNS modification, a hosts-file edit, proxy policies, login modifications, or elevated privileges to make this work.

## Troubleshooting

- **YouTube still works:** Verify the extension was loaded in the Edge profile you're using, SSG8 is running, and **Website Protection** is enabled in SSG8. Click the extension icon to view or pause its state. Existing tabs may remain visible; try a new HTTP(S) navigation in a new tab.
- **Extension says SSG8 is offline:** Check that SSG8 started successfully and no other process already owns TCP port **48765**. Edge and SSG8 must run on the **same Windows VM**.
- **Extension says SSG8 is running but website protection is off:** Browse another page to generate activity; the original SSG8 design intentionally starts with modules OFF and activates them automatically after enough activity. A browser navigation that caused activation may be allowed before the new rule takes effect; subsequent attempts should be blocked.
- **Extension disappears after a restart:** Keep the extension folder at its original location and use `edge://extensions` to reload it.
- **Cannot reach any website after closing SSG8:** Click the extension's **Pause** control or disable the extension through `edge://extensions` (always accessible because internal browser URLs are excluded).

## Security boundaries

- The bridge binds to loopback only and accepts navigation submissions from browser-extension origins using a per-run token.
- No raw URL path, query, content, keystrokes or browsing history is collected.
- No attempts are made to intercept arbitrary Edge sessions without user installation, enforce OS access policies, disable security software, or interfere with recovery controls.
- The simulated self-removal finale stops SSG8, allowing the extension to fail open, rather than deleting Windows files.

## Windows acceptance checks (not yet completed)

- [ ] Edge accepts the manifest and dynamic redirect rule.
- [ ] Website attempts appear as a single corresponding SSG8 log/decision event.
- [ ] After sufficient actions, Website Protection activates automatically and navigation shows the blocked page.
- [ ] Pausing the extension immediately restores navigation.
- [ ] Closing SSG8 or replaying the demo restores normal browsing.
- [ ] SSG8 remains responsive after 50 repeated attempts.

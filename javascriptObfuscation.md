# HTB Academy — JavaScript Deobfuscation Walkthrough

## Overview
This module covers techniques for deobfuscating JavaScript code and decoding encoded strings. Skills covered: source code analysis, JS deobfuscation, base64/hex/rot13 decoding, and curl POST requests.

---

## Section 8 — HTTP Requests

The goal is to replicate what `secret.js` does — sending a POST request to `/serial.php`.

```bash
curl -s http://SERVER_IP:PORT/serial.php -X POST
```

**Response:** A base64 encoded string.

---

## Section 9 — Decoding

The response from the previous step is base64 encoded (identifiable by alphanumeric characters and `=` padding).

**Decode it:**
```bash
echo <base64_string> | base64 -d
```

**Send decoded value as serial:**
```bash
curl -s http://SERVER_IP:PORT/serial.php -X POST -d "serial=DECODED_VALUE"
```

---

## Section 11 — Skills Assessment

### Question 3 — Deobfuscate the code
Use [JSConsole](https://jsconsole.com) or [de4js](https://de4js.kshift.me) to deobfuscate the JavaScript. The `flag` variable is revealed directly in the deobfuscated output:

```
HTB{n3v3r_run_0bfu5c473d_c0d3!}
```

### Question 4 — Replicate the functionality
The deobfuscated code sends a POST request to `/keys.php`. Replicate it:

```bash
curl -s http://SERVER_IP:PORT/keys.php -X POST
```

**Response:** A hex encoded string (only contains `0-9` and `a-f`).

### Question 5 — Decode and submit the key
Decode the hex string:

```bash
echo <hex_string> | xxd -p -r
```

Send the decoded key:
```bash
curl -s http://SERVER_IP:PORT/keys.php -X POST -d "key=DECODED_KEY"
```

**Response:** The final flag.

---

## Key Takeaways
- Always check the page source and linked JS files for sensitive logic
- Common encoding methods: base64, hex, rot13 — each has distinct visual patterns
- Obfuscated JS can be unpacked with tools like [de4js](https://de4js.kshift.me) or [beautifier.io](https://beautifier.io)
- `curl` is a powerful tool for manually replicating browser requests

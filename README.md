# WWPass PHP SDK and API Client Documentation
Version 4.0.2
This repository provides the combined WWPass PHP SDK and Composer-compliant API client library, enabling multifactor authentication for websites and applications. It includes documentation, server library, a standalone script (wwpass.php), and demo examples for easy integration.

## Overview
WWPass is a third-party authentication provider that offers reliable, secure, and convenient multi-factor authentication for websites, as well as mobile and desktop applications. It uses QR-code-based authentication, where users scan a code with the WWPass Key App to log in. Each user is assigned a unique identifier by WWPass, called a PUID (Provider-Specific User Identifier), which ensures consistent identification on the same website while preserving anonymity across different websites.

## Repository Structure
demo/: Contains example code demonstrating WWPass authentication.
src/: Includes the server library classes to interact with the WWPass API.
wwpass.php: A standalone script for implementing WWPass authentication.

## Installation
To install the Composer-compliant API client library:

``` bash
composer require wwpass/apiclient
```

## Usage
The library defines two main classes: **WWPass\Connection** and **WWPass\Exception**.

```php
require_once 'vendor/autoload.php';

try {
    $wwc = new WWPass\Connection([
        'key_file' => WWPASS_SPFE_KEY_FILE,
        'cert_file' => WWPASS_SPFE_CERT_FILE,
        'ca_file' => WWPASS_SPFE_CA_FILE
    ]);
    $response = $wwc->getTicket(['ttl' => 300, 'pin' => true]);

    $ttl = $response['ttl'];
    $ticket = $response['ticket'];
} catch (WWPass\Exception $e) {
    echo 'Caught WWPass exception: ' . $e->getMessage();
} catch (Exception $e) {
    echo 'Caught exception: ' . $e->getMessage();
}
```

## Setup Instructions

> Before following this tutorial, make sure you have installed the WWPass Key App. The application is available for free at [AppStore](https://apps.apple.com/app/wwpass-key/id984532938) and [Google Play](https://play.google.com/store/apps/details?id=com.wwpass.android.passkey).

### Step 1: Register with WWPass

> Skip this section if you already have an account on [manage.wwpass.com](https://manage.wwpass.com/)

- Register your site on the [WWPass Developers](https://manage.wwpass.com/).
- Obtain your Service Provider (SP) credentials (certificate and private key), and download the WWPass CA certificate.

### Step 2: Domain Validation
- Add your domain in the WWPass portal and verify ownership by placing a unique verification file in your website’s root directory. 
- Make sure the file is accessible via a public URL.

### Step 3: Obtain Digital Certificates
- Use OpenSSL to generate a private key and a certificate signing request (CSR):
```bash
openssl req -new -newkey rsa:4096 -nodes -subj "/O=example.org" -keyout example.org.key -out example.org.req
```
- Upload the certificate signing request (CSR) to WWPass and download the issued certificate.

### Step 4: Implement QR Code Authentication
- Add a QR code placeholder to your HTML
```html
<div id="qrcode"></div>
```
- Include the WWPass authentication script to generate and display the QR code:
```js
<script>
  WWPass.authInit({
    qrcode: '#qrcode',
    ticketURL: 'getticket.php',
    callbackURL: 'login.php',
  });
</script>
```
- Ensure your server-side code can handle ticket generation and retrieve the user's PUID.

## License
This project is licensed under the Apache License, Version 2.0. See the [LICENSE](https://www.apache.org/licenses/LICENSE-2.0) file for details.

## Additional Resources
- For more details on implementing WWPass, see the [Documentation](https://docs.wwpass.com/docs/).
- For server library setup, refer to the [Server Library Integration](https://docs.wwpass.com/docs/#step-5-add-server-library).

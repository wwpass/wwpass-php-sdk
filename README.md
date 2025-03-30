# WWPass PHP SDK

The WWPass Web Application SDK for PHP comprises documentation and a library,  that is installed on a Service Provider’s system to allow authentication using the WWPass system. The WWPass Authentication Service is an alternative to, or replacement for, other authentication methods such as user name/password.

### Prerequisites
You have to register your site and receive **WWPass Service Provider (SP) credentials (certificate and private key)** at <https://developers.wwpass.com/>. If, for example, your site has the URL of "mysite.com" and you follow the recommended file naming convention when obtaining SP credentials, the files will be named as mysite.com.crt (for the certificate) and mysite.com.key (for the private key). The [WWPass CA certificate](https://developers.wwpass.com/downloads/wwpass.ca) should also be downloaded and made accessible to WWPass application. If you have root access to your computer, then the /etc/ssl folder is an appropriate place to store the certificates and the key.  Make sure that the script will have enough rights to read the files there. Usually access to /etc/ssl/private is quite limited.

The **WWPass PassKey** or **WWPass PassKey Lite** is a requirement for user authentication. 
**PassKey** is a hardware device that enables authentication and access for a given user.  A major component of the WWPass authentication capability is the software that supports the PassKey itself. Without this software, requests to an end user to authenticate their identity will fail since this software is used to directly access information stored on the PassKey and communicate with WWPass. To allow Administrator testing of the authentication infrastructure, this client software and an accompanying PassKey is required. 
**PassKey Lite** is an application for Android and iOS smartphones and tablets. The application is used to scan QR codes to authenticate into WWPass-enabled sites. Alternatively, when browsing with these mobile devices, you can tap the QR code image to authenticate into the site to access protected information directly on your phone or tablet. 
For more information about how to obtain a PassKey and register it, please refer to the WWPass web site (<http://www.wwpass.com>)  

### Licensing
Copyright 2016 WWPass Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Read more about WWPass PHP SDK in WWPass-PHP-SDK.md



# WWPass PHP SDK and API Client

This repository combines the WWPass PHP SDK and the Composer-compliant WWPass API client library for multifactor authentication and data access.

## Overview

The WWPass system offers a robust authentication service as an alternative to standard methods such as username/password. It includes documentation and a library to integrate WWPass authentication into a service provider's system.

For more detailed information on the standalone SDK, please refer to [WWPass-PHP-SDK.md](WWPass-PHP-SDK.md).

## Installation

To install the Composer-compliant API client library, use the following command:

```bash
$ composer require yourvendor/wwpass-php-sdk
```

## Usage

The library defines two classes in the WWPass namespace: **WWPass\Connection** and **WWPass\Exception**.

```php
require_once 'vendor/autoload.php';

try {
    $wwc = new WWPass\Connection(array(
        'key_file' => WWPASS_SPFE_KEY_FILE,
        'cert_file' => WWPASS_SPFE_CERT_FILE,
        'ca_file' => WWPASS_SPFE_CA_FILE
    ));
    $response = $wwc->getTicket(array(
        'ttl' => 300,
        'pin' => true
    ));

    $ttl = $response['ttl'];
    $ticket = $response['ticket'];
} catch (WWPass\Exception $e) {
    echo 'Caught WWPass exception: ' . $e->getMessage();
} catch (Exception $e) {
    echo 'Caught exception: ' . $e->getMessage();
}
```

## Prerequisites

Service Provider Credentials: Register and obtain certificates and keys at WWPass Developers.
WWPass PassKey or PassKey Lite: Required for authentication. Available for Android and iOS. More information can be found at WWPass.

## License
This project is licensed under the Apache License, Version 2.0.

For more details, view the LICENSE file.


### Key Points

- **Overview**: Provides a concise summary of the combined functionality.
- **Installation**: Simple instructions for Composer-based installations.
- **Usage**: Example code included for quick integration.
- **Prerequisites**: Clearly outlines what is needed to get started.
- **Licensing**: Consolidates the licensing information under the Apache 2.0 License.

This README is structured to give users a comprehensive understanding of your combined repository, ensuring they can install and use your PHP SDK and API client effectively.

# WWPass API for multifactor authentication and data access

Composer-compliant WWPass API client library.

For single-file non-composer library please refer to [https://github.com/wwpass/wwpass-php-sdk](https://github.com/wwpass/wwpass-php-sdk).

## Installation

```bash
$ composer require wwpass/apiclient
```

## Usage

The library defines two classes in the WWPass namespace: **WWPass\Connection** and **WWPass\Exception**.

```php
require_once 'vendor/autoload.php';

try {
    $wwc = new WWPass\Connection(WWPASS_KEY_FILE, WWPASS_CERT_FILE, WWPASS_CA_FILE);
    $ticket = $wwc->getTicket(WWPASS_TICKET_TTL, WWPASS_PIN_REQUIRED?'p':'');
} catch (WWPass\Exception $e) {
    echo 'Caught WWPass exception: ' . $e->getMessage();
} catch (Exception $e) {
    echo 'Caught exception: ' . $e->getMessage();
}
```

## License

The WWPass PHP library is licensed under Apache 2.0 license
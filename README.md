# WWPass PHP SDK and API Client

This repository combines the WWPass PHP SDK and the Composer-compliant WWPass API client library for multifactor authentication and data access.

## Overview

The WWPass system offers a robust authentication service as an alternative to standard methods such as username/password. It includes documentation and a library to integrate WWPass authentication into a service provider's system.

For more detailed information on the standalone SDK, please refer to [WWPass-PHP-SDK.md](WWPass-PHP-SDK.md).

## Installation

To install the Composer-compliant API client library, use the following command:

```bash
$ composer require wwpass/apiclient
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

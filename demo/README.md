# WWPass QR code login on PHP site

This project is a minimalistic implementation of WWPass login for PHP sites. The particular example is kept as slim as possible.

**NOTE.** To deploy the code on your host, first register your site and obtain the WWPass Service Provider SSL certificate. Please follow instructions on the [WWPass Developers](https://manage.wwpass.com) website.

## Installation and running

Provided your web server supports php files ( via e.g. *php-fpm*), copy the project files  into a new directory and point a webserver to the directory. For Linux, it usually means a directory in `/var/www/html`.

Set paths to the WWPass certificate and private key files in `config/config.php`.

## Configuration

WWPass configuration parameters are stored in `config/config.php` file and are as follows:

```php
define('WWPASS_CERT_FILE', "/etc/ssl/example.org.crt");
define('WWPASS_KEY_FILE', "/etc/ssl/example.org.key");
define('WWPASS_CA_FILE', "/etc/ssl/wwpass_sp_ca.crt");
define('WWPASS_PIN_REQUIRED', false);
```

where

- *WWPASS_CERT_FILE* , *WWPASS_KEY_FILE* are paths to the WWPass certificate and private key files respectively,

- *WWPASS_PIN_REQUIRED* when *true*, adds a second factor (PIN or biometry)

## Libraries used

**Server-side.** PHP wwpass/apiclient.

The project includes standalone single-file library `lib/wwpass.php`.

For larger projects you may use composer dependency manager:

```sh
composer require wwpass/apiclient
```


**Client-side.** JavaScript wwpass-frontend.js

Again, to keep the project slim, we use standalone file `js/wwpass-frontend.js`

Alternatively, for an npm-based project, add `wwpass-frontend` as follows:

```sh
npm install wwpass-frontend
```

## Notes

- `getticket.php` file is the new URL, added to your site. The code is identical for all sites.

- `login.php` is responsible for all authentication logic: it contains both server-side functions and browser scripts.

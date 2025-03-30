<?php

/**
 * login.php
 *
 * PHP version 7
 *
 * @category  WWPass_Demo
 * @package   WWPass_PHP_Demo
 * @author    Mikhail Vysogorets <m.vysogorets@wwpass.com>
 * @copyright 2020 WWPass
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

require_once 'config/config.php';
require_once 'lib/wwpass.php';

if (!file_exists(WWPASS_KEY_FILE)) {
    die('<p>Please set <b>config/config.php/WWPASS_KEY_FILE</b> parameter: file does not exist</p>');
}
if (!file_exists(WWPASS_CERT_FILE)) {
    die('<p>Please set <b>config/config.php/WWPASS_CERT_FILE</b> parameter: file does not exist</p>');
}

session_start();


if (array_key_exists('wwp_status', $_REQUEST)) {
    if ($_REQUEST['wwp_status'] != 200) {
    } else {    

        $ticket = $_REQUEST['wwp_ticket'];
        try {
            $wwc = new WWPass\Connection(
                ['key_file' => WWPASS_KEY_FILE, 
                'cert_file' => WWPASS_CERT_FILE, 
                'ca_file' => WWPASS_CA_FILE]
            );
            $puid = $wwc->getPUID(['ticket' => $ticket]);
            $puid = $puid['puid']; 
            $_SESSION['PUID'] = $puid;
            header("Location: index.php");
            exit();
        } catch (WWPass\Exception $e) {
            error_log('Caught WWPass exception: ' . $e->getMessage());
        } catch (Exception $e) {
            error_log('Caught exception: ' . $e->getMessage());
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login -- WWPass demo</title>
    <style>
      h1 {
        text-align:center;
      }
      .qrcode {
        width: 160px;
        height: 160px;
        margin: 40px auto;
      }
    </style>
  </head>

  <body  bgcolor='#E6E6FA'>
    
    <h1>Login with WWPass </h1>
    <div class = 'qrcode'>
    </div>
   
    <script src = 'js/wwpass-frontend.js'></script>
    <script>

      WWPass.authInit({
        qrcode: '.qrcode',
        passkey: document.querySelector('#button--login'),
        ticketURL: 'getticket.php',
        callbackURL: 'login.php',
      });
    </script>
  </body>
</html>

<?php

/**
 * getticket.php
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

try {
    $pin_required = defined('WWPASS_PIN_REQUIRED') ? WWPASS_PIN_REQUIRED : false;
    $wwc = new WWPass\Connection(
        ['key_file' => WWPASS_KEY_FILE, 
        'cert_file' => WWPASS_CERT_FILE, 
        'ca_file' => WWPASS_CA_FILE]
    );
    $ticket = $wwc->getTicket(
        ['pin' => $pin_required]
    );
} catch (WWPass\Exception $e) {
    error_log('Caught WWPass exception: ' . $e->getMessage());
} catch (Exception $e) {
    error_log('Caught exception: ' . $e->getMessage());
}

// Prevent caching.
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Mon, 01 Jan 1996 00:00:00 GMT');

// The JSON standard MIME header.
header('Content-type: application/json');

$data = $ticket;

// Send the data.
echo json_encode($data);

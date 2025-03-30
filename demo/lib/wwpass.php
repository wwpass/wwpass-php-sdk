<?php
/**
 * wwpass.php
 *
 * WWPass Client Library, object style interface (php5+ only) Version 4.0
 *
 * @copyright (c) WWPass Corporation, 2009-2019
 * @author    Rostislav Kondratenko <r.kondratenko@wwpass.com>
 * @author    Vladimir Korshunov <v.korshunov@wwpass.com>
 * @author    Ekaterina Moskovkina <e.moskovkina@wwpass.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace WWPass;

class Exception extends \Exception { }

final class Connection
{
    private $_key_file;
    private $_cert_file;
    private $_ca_file;
    private $_timeout;
    private $_spfe_addr;
    const VERSION = '4.0';

    public function __construct(array $args)
    {
        $this->_key_file = $args['key_file'];
        $this->_cert_file = $args['cert_file'];
        $this->_ca_file = $args['ca_file'];
        if (array_key_exists('timeout', $args)) {
            $this->_timeout = $args['timeout'];
        } else {
            $this->_timeout = 10;
        }
        if (array_key_exists('spfe_addr', $args)) {
            $spfe_addr = $args['spfe_addr'];
        } else {
            $spfe_addr = 'spfe.wwpass.com';
        }
        if (strpos($spfe_addr, '://') === false) {
            $this->_spfe_addr = 'https://' . $spfe_addr;
        } else {
            $this->_spfe_addr = $spfe_addr;
        }
    }

    private function _makeRequest(string $method, string $command, array $data, int $attempts = 3)
    {
        $command_url = $this->_spfe_addr . '/' . $command . '.json';
        $method = strtoupper($method);
        $http_options = array(
            'user_agent' => 'WWPass SDK for PHP, version ' . self::VERSION,
            'timeout' => $this->_timeout,
            'method' => $method,
        );

        switch ($method) {
        case 'GET':
            $command_url .= '?' . http_build_query($data);
            break;
        case 'POST':
            $http_options['header'] = "Content-type: application/x-www-form-urlencoded\r\n";
            $http_options['content'] = http_build_query($data);
            break;
        default:
            throw new Exception('Invalid method ' . $method . ', only GET and POST are accepted');
        }
        $ctx = stream_context_create(
            array(
              'http' => $http_options,
              'ssl' => array(
                'cafile' => $this->_ca_file,
                'local_cert' => $this->_cert_file,
                'local_pk' => $this->_key_file,
              )
            )
        );
        $res = false;
        for ($i = 0; $i < $attempts; $i++) {
            if ($res === false) {
                $res = file_get_contents($command_url, 0, $ctx);
            }
        }
        if ($res === false) {
            $err = error_get_last();
            $message = $err['message'];
            throw new Exception('Cannot communicate to SPFE: ' . $message);
        }
        $result = json_decode($res);
        if ($result->encoding == 'base64') {
            $result->data = base64_decode($result->data);
        }
        if (!$result->result) {
            if (property_exists($result, 'code')) {
                throw new Exception('SPFE returned error: ' . $result->code . ': ' . $result->data);
            }
            throw new Exception('SPFE returned error: ' . $result->data);
        }
        return $result;
    }

    private function _makeAuthTypeString(bool $pin, bool $session_key, bool $client_key)
    {
        $auth_type_str = '';
        if ($pin) {
            $auth_type_str .= 'p';
        }
        if ($session_key) {
            $auth_type_str .= 's';
        }
        if ($client_key) {
            $auth_type_str .= 'c';
        }
        return $auth_type_str;
    }

    public function getName()
    {
        $ticket = $this->getTicket(array(), 0)['ticket'];
        $pos = strpos($ticket, ":");
        if ($pos === false) {
            throw new Exception('Cannot extract service provider name from ticket.');
        }
        return substr($ticket, 0, $pos);
    }

    public function getTicket(array $args)
    {
        if (array_key_exists('pin', $args)) {
            $pin = $args['pin'];
        } else {
            $pin = false;
        }
        if (array_key_exists('session_key', $args)) {
            $session_key = $args['session_key'];
        } else {
            $session_key = false;
        }
        if (array_key_exists('client_key', $args)) {
            $client_key = $args['client_key'];
        } else {
            $client_key = false;
        }
        if (array_key_exists('ttl', $args)) {
            $ttl = $args['ttl'];
        } else {
            $ttl = 120;
        }
        $result = $this->_makeRequest('GET', 'get', array('auth_type' => $this->_makeAuthTypeString($pin, $session_key, $client_key), 'ttl' => $ttl));
        return array('ticket' => $result->data, 'ttl' => $result->ttl);
    }

    public function putTicket(array $args)
    {
        $ticket = $args['ticket'];
        if (array_key_exists('pin', $args)) {
            $pin = $args['pin'];
        } else {
            $pin = false;
        }
        if (array_key_exists('session_key', $args)) {
            $session_key = $args['session_key'];
        } else {
            $session_key = false;
        }
        if (array_key_exists('client_key', $args)) {
            $client_key = $args['client_key'];
        } else {
            $client_key = false;
        }
        if (array_key_exists('ttl', $args)) {
            $ttl = $args['ttl'];
        } else {
            $ttl = 120;
        }
        if (array_key_exists('finalize', $args)) {
            $finalize = $args['finalize'];
        } else {
            $finalize = false;
        }
        if ($finalize) {
            $result = $this->_makeRequest('GET', 'put', array('ticket' => $ticket, 'ttl' => $ttl, 'auth_type' => $this->_makeAuthTypeString($pin, $session_key, $client_key), 'finalize' => 1));
        } else {
            $result = $this->_makeRequest('GET', 'put', array('ticket' => $ticket, 'ttl' => $ttl, 'auth_type' => $this->_makeAuthTypeString($pin, $session_key, $client_key)));
        }
        return array('ticket' => $result->data, 'ttl' => $result->ttl);
    }

    public function getPUID(array $args)
    {
        $ticket = $args['ticket'];
        if (array_key_exists('pin', $args)) {
            $pin = $args['pin'];
        } else {
            $pin = false;
        }
        if (array_key_exists('session_key', $args)) {
            $session_key = $args['session_key'];
        } else {
            $session_key = false;
        }
        if (array_key_exists('client_key', $args)) {
            $client_key = $args['client_key'];
        } else {
            $client_key = false;
        }
        if (array_key_exists('finalize', $args)) {
            $finalize = $args['finalize'];
        } else {
            $finalize = false;
        }
        if ($finalize) {
            $result = $this->_makeRequest('GET', 'puid', array('ticket' => $ticket, 'auth_type' => $this->_makeAuthTypeString($pin, $session_key, $client_key), 'finalize' => 1));
        } else {
            $result = $this->_makeRequest('GET', 'puid', array('ticket' => $ticket, 'auth_type' => $this->_makeAuthTypeString($pin, $session_key, $client_key)));
        }
        return array('puid' => $result->data);
    }

    public function readData(array $args)
    {
        $ticket = $args['ticket'];
        if (array_key_exists('container', $args)) {
            $container = $args['container'];
        } else {
            $container = '';
        }
        if (array_key_exists('finalize', $args)) {
            $finalize = $args['finalize'];
        } else {
            $finalize = false;
        }
        if ($finalize) {
            $result = $this->_makeRequest('GET', 'read', array('ticket' => $ticket, 'container' => $container, 'finalize' => 1));
        } else {
            $result = $this->_makeRequest('GET', 'read', array('ticket' => $ticket, 'container' => $container));
        }
        return array('data' => $result->data);
    }

    public function readDataAndLock(array $args)
    {
        $ticket = $args['ticket'];
        $lock_timeout = $args['lock_timeout'];
        if (array_key_exists('container', $args)) {
            $container = $args['container'];
        } else {
            $container = '';
        }
        $result = $this->_makeRequest('GET', 'read', array('ticket' => $ticket, 'container' => $container, 'to' => $lock_timeout, 'lock' => 1));
        return array('data' => $result->data);
    }

    public function writeData(array $args)
    {
        $ticket = $args['ticket'];
        $data = $args['data'];
        if (array_key_exists('container', $args)) {
            $container = $args['container'];
        } else {
            $container = '';
        }
        if (array_key_exists('finalize', $args)) {
            $finalize = $args['finalize'];
        } else {
            $finalize = false;
        }
        if ($finalize) {
            $this->_makeRequest('POST', 'write', array('ticket' => $ticket, 'data' => $data, 'container' => $container, 'finalize' => 1));
        } else {
            $this->_makeRequest('POST', 'write', array('ticket' => $ticket, 'data' => $data, 'container' => $container));
        }
        return true;
    }

    public function writeDataAndUnlock(array $args)
    {
        $ticket = $args['ticket'];
        $data = $args['data'];
        if (array_key_exists('container', $args)) {
            $container = $args['container'];
        } else {
            $container = '';
        }
        if (array_key_exists('finalize', $args)) {
            $finalize = $args['finalize'];
        } else {
            $finalize = false;
        }
        if ($finalize) {
            $this->_makeRequest('POST', 'write', array('ticket' => $ticket, 'data' => $data, 'container' => $container, 'unlock' => 1, 'finalize' => 1));
        } else {
            $this->_makeRequest('POST', 'write', array('ticket' => $ticket, 'data' => $data, 'container' => $container, 'unlock' => 1));
        }
        return true;
    }

    public function lock(array $args)
    {
        $ticket = $args['ticket'];
        $lock_timeout = $args['lock_timeout'];
        if (array_key_exists('lockid', $args)) {
            $lockid = $args['lockid'];
        } else {
            $lockid = '';
        }
        $this->_makeRequest('GET', 'lock', array('ticket' => $ticket, 'to' => $lock_timeout, 'lockid' => $lockid));
        return true;
    }

    public function unlock(array $args)
    {
        $ticket = $args['ticket'];
        if (array_key_exists('lockid', $args)) {
            $lockid = $args['lockid'];
        } else {
            $lockid = '';
        }
        if (array_key_exists('finalize', $args)) {
            $finalize = $args['finalize'];
        } else {
            $finalize = false;
        }
        if ($finalize) {
            $this->_makeRequest('GET', 'unlock', array('ticket' => $ticket, 'lockid' => $lockid, 'finalize' => 1));
        } else {
            $this->_makeRequest('GET', 'unlock', array('ticket' => $ticket, 'lockid' => $lockid));
        }
        return true;
    }

    public function getSessionKey(array $args)
    {
        $ticket = $args['ticket'];
        if (array_key_exists('finalize', $args)) {
            $finalize = $args['finalize'];
        } else {
            $finalize = false;
        }
        if ($finalize) {
            $result = $this->_makeRequest('GET', 'key', array('ticket' => $ticket, 'finalize' => 1));
        } else {
            $result = $this->_makeRequest('GET', 'key', array('ticket' => $ticket));
        }
        return array('sessionKey' => $result->data);
    }

    public function createPFID(string $data = '')
    {
        if ($data) {
            $result = $this->_makeRequest('POST', 'sp/create', array('data' => $data));
        } else {
            $result = $this->_makeRequest('GET', 'sp/create', array('data' => ''));
        }
        return array('pfid' => $result->data);
    }

    public function removePFID(string $pfid)
    {
        $this->_makeRequest('GET', 'sp/remove', array('pfid' => $pfid));
        return true;
    }

    public function readDataSP(string $pfid)
    {
        $result = $this->_makeRequest('GET', 'sp/read', array('pfid' => $pfid));
        return array('data' => $result->data);
    }

    public function readDataSPandLock(array $args)
    {
        $pfid = $args['pfid'];
        $lock_timeout = $args['lock_timeout'];
        $result = $this->_makeRequest('GET', 'sp/read', array('pfid' => $pfid, 'to' => $lock_timeout, 'lock' => 1));
        return array('data' => $result->data);
    }

    public function writeDataSP(array $args)
    {
        $pfid = $args['pfid'];
        $data = $args['data'];
        $this->_makeRequest('POST', 'sp/write', array('pfid' => $pfid, 'data' => $data));
        return true;
    }

    public function writeDataSPandUnlock(array $args)
    {
        $pfid = $args['pfid'];
        $data = $args['data'];
        $this->_makeRequest('POST', 'sp/write', array('pfid' => $pfid, 'data' => $data, 'lock' => 1));
        return true;
    }

    public function lockSP(array $args)
    {
        $lockid = $args['lockid'];
        $lock_timeout = $args['lock_timeout'];
        $this->_makeRequest('GET', 'sp/lock', array('to' => $lock_timeout, 'lockid' => $lockid));
        return true;
    }

    public function unlockSP(string $lockid)
    {
        $this->_makeRequest('GET', 'sp/unlock', array('lockid' => $lockid));
        return true;
    }

    public function getClientKey(string $ticket)
    {
        $result = $this->_makeRequest('GET', 'clientkey', array('ticket' => $ticket));
        $result_arr = array('clientKey' => $result->data, 'ttl' => $result->ttl);
        if (property_exists($result, 'originalTicket')) {
            $result_arr['originalTicket'] = $result->originalTicket;
        }
        return $result_arr;
    }
}

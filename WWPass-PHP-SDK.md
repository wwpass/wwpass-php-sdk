# WWPass PHP SDK
Version 3.0

May 2014
 
## CHAPTER 1 - OVERVIEW
### Introduction
The *WWPass PHP SDK* comprises a library, examples and documentation that is installed on a Service Provider's system to allow authentication using the WWPass system.  The WWPass Authentication Service is an alternative to, or replacement for, other authentication methods such as user name/password.

The sections that follow describe language-specific API calls associated with the WWPass Authentication Service.  Each reference will describe the declaration of the API, the parameters required and their meaning, followed by the expected return value(s) and raised exceptions, if any.  

The **WWPass PassKey** or **WWPass PassKey Lite** is a requirement for user authentication. 
**PassKey** is a hardware device that enables authentication and access for a given user.  A major component of the WWPass authentication capability is the software that supports the PassKey itself. Without this software, requests to an end user to authenticate their identity will fail since this software is used to directly access information stored on the PassKey and communicate with WWPass. To allow Administrator testing of the authentication infrastructure, this client software and an accompanying PassKey is required. 
**PassKey Lite** is an application for Android and iOS smartphones and tablets. The application is used to scan QR codes to authenticate into WWPass-enabled sites. Alternatively, when browsing with these mobile devices, you can tap the QR code image to authenticate into the site to access protected information directly on your phone or tablet. 
For more information about how to obtain a PassKey and register it, please refer to the WWPass web site (<http://www.wwpass.com>)  

### Licensing
The *WWPass PHP SDK* is licensed under the Apache 2.0 license.  This license applies to all source code, code examples and accompanying documentation contained herein.  You can modify and re-distribute the code with the appropriate attribution.  This software is subject to change without notice and should not be construed as a commitment by WWPass.

You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, the software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

### Customer Assistance
If you encounter a problem or have a question, you can contact the WWPass Service Desk as follows:
Phone - 1-888-WWPASS1 (+1-888-997-2771)
Email - <support@wwpass.com>
Online - [Support form](https://www.wwpass.com/support/)


## CHAPTER 2 - PHP PACKAGE
### About the WWPass PHP Authentication Library
The PHP library consists of a single file that defines a single class: WWPassConnection.  A new connection is initiated every time a request is made.  This library depends on the PHP cURL library with SSL support.

#### Class WWPassConnection
##### Declaration
    WWPassConnection($key_file, $cert_file, $ca_file, $timeout=10, $spfe_addr='spfe.wwpass.com')
##### Purpose
*WWPassConnection* is the class for a WWPass SPFE connection, and a new connection is initiated every time a connection request is made.  The WWPass CA certificate is required for validating the SPFE certificate and can be downloaded at <https://developers.wwpass.com/downloads/wwpass.ca>
##### Parameters
| Name | Description |
| --------- | ---------------- | 
| $key_file | The path to the Service Provider's private key file. |
| $cert_file | The path to the Service Provider's certificate file. |
| $timeout | Timeout of requests to SPFE measured in seconds. It is used in all operations. The default is 10 seconds. |
| $spfe_addr | The hostname or base URL of the SPFE. The default name is <https://spfe.wwpass.com>. |
##### Exception (Throw)
*WWPassException* is thrown.
 

### Functions 
The following functions return the requested result in the case of success or, through the *WWPassException*, an appropriate exception message in the case of failure.

#### getName()
##### Declaration
    WWPassConnection.getName()
##### Purpose
Calls to this function get the SP name on the certificate which was used for initiate this *WWPassConnection* instance. This helper function may be used during automatic configuration of authentication modules, for example.  Do not use it every time user is authenticated.  The function is time – and resource – consuming.
##### Returns
SP name
##### Throws
    WWPassException (SPFE returned ticket without a colon.)
	
#### getTicket()
##### Declaration
    WWPassConnection.getTicket($ttl = 120, $auth_types = '')
##### Purpose
Calls to this function get a newly-issued ticket from SPFE. (This particular form relates to so-called “counter-clockwise” protocol.)
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ttl | The period in seconds for the ticket to remain valid since issuance. The default is 120 seconds. |
| $auth_types | Defines which credentials will be asked of the user to authenticate this ticket. The values may be any combination of following letters: ‘p’ — to ask for PassKey and access code; ‘s’ — to generate cryptographically secure random number that would be available both to client and Service Provider; or empty string to ask for PassKey only (default). |
##### Returns
Ticket issued by the SPFE.
##### Throws
    WWPassException

#### putTicket()
##### Declaration
    WWPassConnection.putTicket($ticket, $ttl = 120, $auth_types = '')
##### Purpose
A call to this function checks the authentication of the ticket and may issue a new ticket from SPFE.  All subsequent operations should use a returned ticket instead of one provided to *putTicket*.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The ticket to validate. |
| $ttl | The period in seconds for the ticket to remain valid since issuance. The default is 120 seconds. |
| $auth_types | Defines which credentials will be asked of the user to authenticate this ticket. The values may be any combination of following letters: ‘p’ — to ask for PassKey and access code; ‘s’ — to generate cryptographically secure random number that would be available both to client and Service Provider; or empty string to ask for PassKey only (default). |
##### Returns
Original or newly-issued ticket. The new ticket should be used in further operations with the SPFE.
##### Throws
    WWPassException
	
#### getPUID()
#### Declaration
    WWPassConnection.getPUID($ticket, $auth_types = '', $finalize = false)
##### Purpose
*WWPassConnection.getPUID* gets the id of the user from the Service Provider Front End. This ID is unique for each Service Provider.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket. |
| $auth_types | Defines which credentials will be asked of the user to authenticate this ticket. The values may be any combination of following letters: ‘p’ — to ask for PassKey and access code; ‘s’ — to generate cryptographically secure random number that would be available both to client and Service Provider; or empty string to ask for PassKey only (default). |
| $finalize | Set to ‘true’ value to close the ticket after this operation is finished. |
##### Returns
Returns the PUID issued by the SPFE. 
##### Throws
    WWPassException

#### readData()
##### Declaration
    WWPassConnection.readData($ticket, $container = '', $finalize = false)
##### Purpose
Calls to this function request data stored in the user’s data container.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket issued by the SPFE. |
| $container | Arbitrary string (only the first 32 bytes are significant) identifying the user’s data container. |
| $finalize | Set to ‘true’ value to invalidate the ticket after this operation is finished. |
##### Returns
Returns the data stored in the user’s data container.  Returns empty string if the data container does not exist. 
##### Throws
    WWPassException
 
#### readDataAndLock()
##### Declaration
    WWPassConnection.readDataAndLock($ticket, $lock_timeout, $container = '')
##### Purpose
Calls to this function request data stored in the user’s data container and locks an advisory lock with the same name as the name of the data container.  Each WWPass lock has a name or “lock id.”  This function operates locks with the same name as the pertinent data container.
**Note:** The lock does not lock the data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket issued by the SPFE. |
| $lock_timeout | The period in seconds for the data container to remain protected from the new data being accessed. |
| $container | Arbitrary string (only the first 32 bytes are significant) identifying the user’s data container. |
##### Returns
Returns the data stored in the user’s data container.  Returns empty string if the data container does not exist.   
##### Throws
    WWPassException
 
#### writeData()
##### Declaration
    WWPassConnection.writeData($ticket, $data, $container = '', $finalize = false)
##### Purpose
Calls to this function write data into the user’s data container.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket issued by the SPFE. |
| $data | The string to write into the container. |
| $container | Arbitrary string (only the first 32 bytes are significant) identifying the user’s data container. |
| $finalize | Set to ‘true’ value to close the ticket after this operation is finished. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException
 
#### writeDataAndUnlock()
##### Declaration
    WWPassConnection.writeDataAndUnlock($ticket, $data, $container = '', $finalize = false)
##### Purpose
Calls to this function writes data into the user’s data container and unlocks an advisory lock with the same name as the name of the data container.  Each WWPass lock has a name or “lock id.”  This function operates locks with the same name as the pertinent data container.
**Note:** The lock does not lock the data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket issued by the SPFE. |
| $data | The string to write into the container. |
| $container | Arbitrary string (only the first 32 bytes are significant) identifying the user’s data container. |
| $finalize | Set to ‘true’ value to close the ticket after this operation is finished. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException

#### lock()
##### Declaration
    WWPassConnection.lock($ticket, $lock_timeout, $lockid = '')
##### Purpose
Calls to this function locks an advisory lock identified by the user (by authenticated ticket) and lock ID. 
**Note:** The lock does not lock any data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket issued by the SPFE. |
| $lock_timeout | The period in seconds for the data container to remain protected from the new data being accessed. |
| $lockid | The arbitrary string (only the first 32 bytes are significant) identifying the lock. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException
 
#### unlock()
##### Declaration
    WWPassConnection.unlock($ticket, $lockid = '', $finalize = false)
##### Purpose
Calls to this function unlocks an advisory lock identified by the user (by authenticated ticket) and lock ID. 
**Note:** The lock does not lock any data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket issued by the SPFE. |
| $lockid | The arbitrary string (only the first 32 bytes are significant) identifying the lock. |
| $finalize | Set to ‘true’ value to close the ticket after this operation is finished. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException
 
#### getSessionKey()
##### Declaration
    WWPassConnection.getSessionKey($ticket, $finalize = false)
##### Purpose
*WWPassConnection. getSessionKey* return cryptographically secure random number generated for the authentication transaction that is identified by ticket. This value can be used do derive cryptographic keys that will secure communication between client and Service Provider. Note that this key will be available only if the ticket was generated with 's' auth type.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $ticket | The authenticated ticket that was generated with 's' auth type. |
| $finalize | Set to ‘true’ value to close the ticket after this operation is finished. |
##### Returns
Returns the Session Key.
##### Throws
    WWPassException

#### createPFID()
##### Declaration
    WWPassConnection.createPFID($data = '')
##### Purpose
A call to this function creates a new SP-only container with a unique name and returns its name.  If the data parameter is provided, it writes data to this container.  Concurrent create requests will never return the same PFID.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $data | The data to write to the container. |
##### Returns
Returns the identifier of the newly-created data container.
##### Throws
    WWPassException
	
#### removePFID()
##### Declaration
    WWPassConnection.removePFID($pfid)
##### Purpose
Destroys the SP-specific data container.  The container will then become non-existent as if it were never created.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $pfid | The PFID of the data container to destroy. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException
 
#### readDataSP()
##### Declaration
    WWPassConnection.readDataSP($pfid)
##### Purpose
Calls to this function request data stored in the SP-specific data container.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $pfid | The PFID of the data container as returned by *createPFID*. |
##### Returns
Returns the data stored in PFID-designated SP data container, or an empty string if the data container does not exist.
##### Throws
    WWPassException
	
#### readDataSPandLock()
##### Declaration
    WWPassConnection.readDataSPandLock($pfid, $lock_timeout)
##### Purpose
Calls to this function request data stored in the Service Provider's data container and locks an advisory lock with the same name as the name of the data container.  Each WWPass lock has a name or “lock id.”  This function operates locks with the same name as the pertinent data container.
**Note:** The lock does not lock the data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $pfid | The Data Container Identifier as returned by *createPFID*. |
| $lock_timeout | The period in seconds for the data container to remain protected from the new data being accessed. |
##### Returns
Returns the data stored in the Service Provider's data container; returns ‘NULL’ character sequence if the data container does not exist.
##### Throws
    WWPassException
	
#### writeDataSP()
##### Declaration
    WWPassConnection.writeDataSP($pfid, $data)
##### Purpose
Writes data into the SP-specific data container.
##### Parameters
| Name | Description |
| ------- | -------------- |
| $pfid | The Data Container Identifier as returned by *createPFID*. |
| $data | The string to write into the container. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException  

#### writeDataSPandUnlock()
##### Declaration
    WWPassConnection.writeDataSPandUnlock($pfid, $data)
##### Purpose
Calls to this function writes data into the Service Provider’s data container and unlocks an advisory lock with the same name as the name of the data container.  Each WWPass lock has a name or “lock id.”  This function operates locks with the same name as the pertinent data container.
**Note:** The lock does not lock the data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $pfid | The Data Container Identifier as returned by *createPFID*. |
| $data | The string to write into the container. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException  
 
#### lockSP()
##### Declaration
    WWPassConnection.lockSP($lockid, $lock_timeout)
##### Purpose
Calls to this function locks an advisory lock identified by the lock ID. 
**Note:** The lock does not lock any data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $lockid | The arbitrary string (only the first 32 bytes are significant) identifying the lock. |
| $lock_timeout | The period in seconds for the SP data to remain protected from the new data being accessed. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException  

#### unlockSP()
##### Declaration
    WWPassConnection.unlockSP($lockid)
##### Purpose
Calls to this function unlocks an advisory lock identified by the lock ID. 
**Note:** The lock does not lock any data container.  It locks only itself, a common behavior to locks/flags/semaphores in other languages/APIs – so-called “advisory locks.”
##### Parameters
| Name | Description |
| ------- | -------------- |
| $lockid | The arbitrary string (only the first 32 bytes are significant) identifying the lock. |
##### Returns
Returns nothing.   
##### Throws
    WWPassException  
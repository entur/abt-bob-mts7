# `Simple` artifacts
Support for creating a simple (low-level) MTS7 card representation. The card essentially consists of APDU command and responses.

This approach considerably simplifies the clients. Advantages:

 * Not longer necessary:
   * parse TLV and CBOR content
   * maintaining a list of issuer certificates
   * EC / RSA signature verification
 * Centralized logic
 * Low-level debugging
 
Disadvantages:

 * Increased data transfer size 

## Reader
Talks to the MTS7 card:

 * issues the relevant commands
    * select
    * get (next) data
    * internal authenticate
 * only looks at APDU response codes
    * issues `continue` type commands in case a single response is split into multiple responses
 * does not parse APDU response data

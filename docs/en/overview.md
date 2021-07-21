# Overview

## High Level Summary

- Email is sent encrypted using S/MIME over standard SMTP
  - Before it is sent the content is
    - Encrypted using the public key provided by recipient
    - Signed using the private key provided by sender
    - Both operations are carried out using OpenSSL v1.1.1
- Email is received and
  - Decrypted using private key provided by recipient
  - Signature authenticated using the public key provided by sender
  - Both operations carried out by software available on the client
    - e.g: OpenSSL or an email client such Microsoft Outlook

## Dependencies

- SwiftMailer
  - Free feature-rich PHP mailer
  - swiftmailer/swiftmailer composer package
    - installed by silverstripe/framework
- OpenSSL
  - ^1.1.1
- SSL keys
  - Pair of keys for encrypting emails
  - Pair of keys for signing emails (optional)

## Process Flow

Once the application is configured to use the S/MIME mailer class when
processing a "Contact Us" form for example, a typical process flow for a form
submission is generally as follows.

- Client initiates POST request after submitting a web form
  - POST request includes data entered at client
  - POST request often encrypted in transit using TLS/SSL
- Web server receives request
  - Web server process assigned to handle request
  - Loads PHP
  - Stores $GLOBALS in memory, this includes POST data
  - Stores files uploaded via POST in /tmp/
  - Memory freed and /tmp/ folder files deleted when processing request
    completes
- Application processing
  - Entry point index.php
  - Request object is built
    - $request = HTTPRequestBuilder::createFromEnvironment();
    - Build with env vars and PHP $GLOBALS
    - Including _REQUEST and _POST
  - Request is handled
    - Director::handleRequest
    - Calls middleware
    - Hands off to controller
  - Form data handled
    - FormRequestHandler::httpSubmission
    - Loads data from the POST request
    - Validate data
    - Hands off to Controller for further form handling
  - Controller
    - POST data available from memory and filesystem
    - Data compiled into Email
      - Along with file attachments if necessary
    - SMIMEMailer instantiated to act as the Mailer, responsible for actually
      sending emails
      - Key paths and pass phrases passed as arguments
      - SMIMEMailer::send instantiates signer Swift_Signers_SMimeSigner with
        available keys
      - Attaches the signer object to the message and hands off to SwiftMailer
        for sending
    - Email is encrypted and signed accordingly prior to sending by handing off
      to PHP OpenSSL extension

# Configuration

Configuring this module for use requires creation of SSL keys for encryption and/or signing messages, instantiating the mailer with those keys and
handing off to the mailer for sending of emails.

Generation of self-signed keys
==============================

Certificates need to be PEM encoded in order to work with SwiftMailer / S/MIME.

This documentation is based on [this post](https://www.dalesandro.net/create-self-signed-smime-certificates/), which specifically uses Windows, so there will be differences.

In either case, we will essentially be creating **two** key-pairs to use for signing and encrypting the email.

1.  One is the self-signed certificate and private key pair used for signing the email.

    1.  This will be signed by our own self generated certificate authority (CA), which we will create the certificate and key for

2.  The other is a self-signed certificate and private key pair used for encrypting the email.

    1.  This will be signed by our own self generated CA, which we will create the certificate and key for


In both cases the process (which follows) to generate the key pair is the same. **In order to create 2 key pairs you need to run through these steps twice.** These steps can be carried out on:

1.  the server or virtual machine which is sending the email, the key pair generated on this machine can be used to sign the email

2.  the local or host machine which is receiving the email, the key pair generated on this machine can be used to encrypt the email


During initial setup and testing, both key pairs can rest on the server, as encrypting and decrypting tests can be run via command line.

This section is intended for use only when testing.

Create OpenSSL configuration file for use with emailProtection
--------------------------------------------------------------

Create a new configuration include.
```
cd
mkdir .smime
chmod 700 .smime
cd .smime
touch smime.cnf
```

`vi smime.cnf` and add the following:
```
[req]
distinguished_name = req_distinguished_name
encrypt_key  = no

[req_distinguished_name]
countryName = Country Name (2 letter code)
countryName_default = NZ
countryName_min = 2
countryName_max = 2
stateOrProvinceName = State or Province Name
stateOrProvinceName_default = Auckland
localityName = Locality Name (e.g: city)
localityName_default = Auckland
0.organizationName = Organization Name (eg, company)
0.organizationName_default = Agency Ltd Test
organizationalUnitName = Organizational Unit Name (e.g: department)
organizationalUnitName_default = Bespoke
commonName = Common Name (e.g: server FQDN or YOUR name)
commonName_default = Test
commonName_max = 64
emailAddress = Email Address (e.g: your email address)
emailAddress_max = 40

[smime]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = email:copy
extendedKeyUsage = emailProtection
```

Config file docs can be found here: [https://www.openssl.org/docs/man1.1.1/man5/config.html](https://www.openssl.org/docs/man1.1.1/man5/config.html)

Configuration file format for the `[req]` and associated `[req_distinguished_name]` sections above can be found here: [https://www.openssl.org/docs/man1.1.1/man1/openssl-req.html](https://www.openssl.org/docs/man1.1.1/man1/openssl-req.html).

Some relevant config file docs for the \[smime\] section can be found here: [https://www.openssl.org/docs/man1.1.1/man5/x509v3_config.html](https://www.openssl.org/docs/man1.1.1/man5/x509v3_config.html). The key configuration here is `extendedKeyUsage = emailProtection`.

Generate CA private key
-----------------------

### RSA

`openssl genrsa -out ca.key 4096`

[https://www.openssl.org/docs/man1.0.2/man1/genrsa.html](https://www.openssl.org/docs/man1.0.2/man1/genrsa.html)

*   genrsa

    *   generate RSA private key

*   out

    *   the private key file to spit out

*   4096

    *   size of private key to generate in bits

We end up with ca.key, a PEM encoded file which contains the private key of the CA.

Generate CA certificate
-----------------------

The certificate will contain the public key for the CA.

`openssl req -config smime.cnf -new -nodes -x509 -sha384 -days 30 -key ca.key -out ca.crt`

[https://www.openssl.org/docs/man1.0.2/man1/openssl-req.html](https://www.openssl.org/docs/man1.0.2/man1/openssl-req.html)

*   req

    *   creates and processes certificate requests

    *   can also create self signed certs

*   new

    *   generate a new certificate request

    *   prompts user for relevant field values

    *   if -key option is not used it will generate a new RSA private key

*   nodes

    *   if a private key is created it will not be encrypted

*   x509

    *   outputs a self signed cert instead of a certificate signing request

    *   typically to generate a test cert or self signed root CA

    *   a large random number used for the serial number (unless set_serial option specified)

*   sha384

    *   specifies the message digest (output of the sha384 hash function) to sign the request with

    *   override the digest algo specified in the config file

    *   some public key algorithms might override this choice

    *   any algo supported by `openssl dgst --help` can be used

*   days

    *   when x509 format used this specifies the number of days to certify the cert for, default is 30

*   key

    *   file to read private key from

*   out

    *   output filename to write to, standard output by default


We end up with ca.crt, a PEM encoded self signed cert for the CA in x.509 format.

### Example

It can be useful to use different details when prompted for certificate information to keep track of the set up e.g:

*   Server CA: Internal Test, Devops

*   Server leaf: Test environment details

*   Host CA: Internal Test, Bespoke

*   Host leaf: Host environment details

```
openssl req -config smime.cnf -new -nodes -x509 -sha384 -days 30 -key ca.key -out ca.crt
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [NZ]:
State or Province Name [Auckland]:
Locality Name (e.g: city) [Auckland]:
Organization Name (eg, company) [Agency Test]:
Organizational Unit Name (e.g: department) [Bespoke]:Devops
Common Name (e.g: server FQDN or YOUR name) [Test]:client.local
Email Address (e.g: your email address) []:ca@example.com
```

We end up with ca.crt, which is the self signed cert in x.509 format. Let’s look at the contents:
```
openssl x509 -in ca.crt -noout -text
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            43:5b:22:...:ee:b1
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C = NZ, ST = Auckland, L = Auckland, O = Agency Test, OU = Devops, CN = client.local, emailAddress = "ca@example.com"
        Validity
            Not Before: Nov 24 01:23:08 2020 GMT
            Not After : Dec 24 01:23:08 2020 GMT
        Subject: C = NZ, ST = Auckland, L = Auckland, O = Agency Test, OU = Devops, CN = client.local, emailAddress = "ca@example.com"
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:fb:22:...:62:fa:
                    ...
                ASN1 OID: secp384r1
                NIST CURVE: P-384
    Signature Algorithm: ecdsa-with-SHA384
         30:64:02:...:b2:b6:
         22:ff:41:...:29:db:
         ...
```
Let's check if it is PEM encoded:

`openssl x509 -inform PEM -in ca.crt -text -noout`

If there is an error with the above command it might be that the file is DER encoded instead of PEM. Try viewing the file:

`cat ca.crt`

A PEM encoded certificate:

*   will likely be ASCII-readable

*   it will have a line -----BEGIN CERTIFICATE-----, followed by base64-encoded data, followed by a line -----END CERTIFICATE-----

*   there may be other lines before or after

*   each line must be maximum 79 characters long


Generate leaf private key
-------------------------

Generate the _Certificate_ private key, the private key of the key pair we wish to use directly, as opposed to the CA private key above.

### RSA

`openssl genrsa -aes256 -out client-smime-<ENV>.key 4096`

[https://www.openssl.org/docs/man1.0.2/man1/genrsa.html](https://www.openssl.org/docs/man1.0.2/man1/genrsa.html)

*   genrsa

    *   generate RSA private key

*   aes256

    *   encrypt the key with aes256 cipher before outputting it

    *   if an option like this is not specified no encryption is used

    *   prompted for password unless using -passout option

*   out

    *   the private key file to spit out

*   4096

    *   size of private key to generate in bits


Enter a password of suitable strength when prompted.

We end up with client-smime-<ENV>.key, a PEM encoded file which contains the private key of our key pair.

Can also check if this private key is PEM encoded, if there are no errors with the below command then it is:

`openssl rsa -inform PEM -in client-smime-<ENV>.key -text -noout`

Generate leaf certificate signing request
-----------------------------------------

`openssl req -config smime.cnf -new -key client-smime-<ENV>.key -out client-smime-<ENV>.csr`

[https://www.openssl.org/docs/man1.0.2/man1/openssl-req.html](https://www.openssl.org/docs/man1.0.2/man1/openssl-req.html)

*   req

    *   creates and processes certificate signing requests

    *   can also create self signed certs

*   config

    *   allow alt config file to be specified to override compile time filename or OPENSSL_CONF env var

*   new

    *   generate a new certificate signing request

    *   prompts user for relevant field values

    *   if -key option is not used it will generate a new RSA private key

*   key

    *   specifies the file to read the private key from

*   out

    *   output filename to write to, standard output by default


You will be prompted to fill out the certificate information.

### Example
```
openssl req -config smime.cnf -new -key client-smime-host.key -out client-smime-host.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [NZ]:
State or Province Name [Auckland]:
Locality Name (e.g: city) [Auckland]:
Organization Name (eg, company) [Agency Test]:
Organizational Unit Name (e.g: department) [Bespoke]:
Common Name (e.g: server FQDN or YOUR name) [Test]:
Email Address (e.g: your email address) []:test@example.com
```

We end up with client-smime-<ENV>.csr, PEM encoded certificate signing request.

Generate leaf certificate
-------------------------

`openssl x509 -req -in client-smime-<ENV>.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client-smime-<ENV>.crt`

[https://www.openssl.org/docs/man1.0.2/man1/x509.html](https://www.openssl.org/docs/man1.0.2/man1/x509.html)

*   x509

    *   multi purpose certificate utility

    *   display cert information

    *   convert certs to various forms

    *   sign cert requests like a CA

    *   edit certificate trust settings

*   req

    *   a certificate signing request is expected as input, instead of the default which is to expect a certificate as input

*   in

    *   input filename to read certificate or csr from, default is standard input

*   CA

    *   specifies the CA cert to be used for signing

    *   with this option x509 acts like a CA

    *   input file is signed by this CA, its issuer name is set to the subject name of the CA and it is digitally signed using the CAs private key

    *   usually used with req option

*   CAKey

    *   set the CA private key to sign the cert with

    *   if option is not present, CA private key assumed to be within the CA certificate file

*   CAcreateserial

    *   CA serial number file is created if it does not exist

    *   populates file with serial number

    *   the cert being signed will have it as its serial number

    *   if CA option is specified and the serial number file does not exist it is an error

*   out

    *   output filename to write to or standard output by default


We end up with ca.srl, a file containing a serial number, and client-smime-<ENV>.crt our PEM encoded, x.509 format certificate.

### Example

Lets check if CRT is PEM encoded:

`openssl x509 -inform PEM -in client-smime-<ENV>.crt -text -noout`

If there is an error it is likely due to file being DER encoded.
```
openssl x509 -inform PEM -in client-smime-host.crt -text -noout
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 4A90215A... (0xdf58...)
    Signature Algorithm: ecdsa-with-SHA1
        Issuer: C = NZ, ST = Auckland, L = Auckland, O = Agency Test, OU = Devops, CN = client.local, emailAddress = "ca@example.com"
        Validity
            Not Before: Nov 24 00:52:25 2020 GMT
            Not After : Dec 24 00:52:25 2020 GMT
        Subject: C=NZ, ST=Auckland, L=Auckland, O=Agency Test, OU=Bespoke, CN=Test/emailAddress=test@example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:d0:0c:...:71:3e:
                    ...
                ASN1 OID: secp384r1
                NIST CURVE: P-384
    Signature Algorithm: ecdsa-with-SHA1
         30:65:02:...:2b:27:
         ...
```
Can check that the serial number matches the contents of the ca.srl file:
```
cat ca.srl
4A90215A...
```

Summary
-------

We have generated a public/private key pair for our own certificate authority (CA). We have generated a public/private key pair for application use, which is signed by the private key of the CA above. Our public keys are stored in x.509 formatted, PEM encoded certificates. We can now provide our public keys to third parties.

You should end up with these files

*   `ca.crt`

*   `ca.key`

*   `client-smime-<ENV>.key`

*   `client-smime-<ENV>.crt`

*   `ca.srl`


Next steps
----------

We can use the key pair we have generated and signed, for encrypting or signing SMIME messages. In order to provide the keypair to Microsoft Outlook it can be useful to bundle everything into a `.p12` archive for importing into outlook.

### Bundle into p12

PKCS #12 defines an archive file format for storing many cryptography objects as a single file. It is commonly used to bundle a private key with its X.509 certificate or to bundle all the members of a chain of trust.

`openssl pkcs12 -export -in client-smime-<ENV>.crt -inkey client-smime-<ENV>.key -out client-smime-<ENV>.p12`

[https://www.openssl.org/docs/man1.0.2/man1/pkcs12.html](https://www.openssl.org/docs/man1.0.2/man1/pkcs12.html)

*   pkcs12

    *   pkcs12 command allows PKCS#12 files (sometimes referred to as PFX files) to be created and parsed

    *   these files are used by several programs such as Microsoft Outlook

*   export

    *   specifies that a PKCS#12 file will be created rather than parsed

*   in

    *   filename to read certs and private keys from

    *   must all be in PEM format

    *   one private key and its corresponding certificate should be present

    *   any additional certs present will be included in the PKCS#12 file

*   inkey

    *   file to read private key from

*   out

    *   filename to write the PKCS#12 file to


Once again you’ll be prompted for passwords, or which you can use an appropriate string.
```
Enter pass phrase for smime_test_user.key:
Enter Export Password:
Verifying - Enter Export Password:
```

That’s it! You now have a bunch of keys and certificates. The `.p12` bundle is for use with your email client.

# Instantiating Mailer

Store the encryption cert and any signing certs and keys somewhere secure on the server.
Commonly we can provide the paths to the application via Environment variables, which
facilitates using different files per environment.

```conf
# SMIME CONFIGURATION
DISABLE_SMIME=false

SS_SMIME_ENCRYPT_CERT="/var/www/secure/client-smime-host.crt" # Encryption cert location
SS_SMIME_SIGN_CERT="/var/www/secure/client-smime-local.crt" # Signing cert location
SS_SMIME_SIGN_KEY="/var/www/secure/client-smime-local.key" # Signing key location
SS_SMIME_SIGN_PASS="password" # Signing key passphrase, optional
```

Then instantiate the mailer in the Controller where an Email is created and sent.

```php
// Create email
$email = new Email(
    'from@example.com',
    'to@example.com',
    'Test S/MIME encrypted emails'.
    'Email body, test 123'
);

// Always encrypt on production or other environments if they do not have SMIME disabled
if (Director::isLive() || !Environment::getEnv('DISABLE_SMIME')) {
    Injector::inst()->registerService(
        SMIMEMailer::create(
            Environment::getEnv('SS_SMIME_ENCRYPT_CERT'),
            Environment::getEnv('SS_SMIME_SIGN_CERT'),
            Environment::getEnv('SS_SMIME_SIGN_KEY'),
            Environment::getEnv('SS_SMIME_SIGN_PASS'),
        ),
        Mailer::class
    );
}

try {
    $email->sendPlain();
} catch (Exception $exception) {
    $form->sessionMessage(
        _t('ContactForm.ERRORMESSAGE', 'Something went wrong with your submission.'),
        'bad'
    );
    $this->redirectBack();
}
```

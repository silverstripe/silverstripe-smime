<?php

namespace SilverStripe\SMIME\Control;

use SilverStripe\Control\Email\Email;
use SilverStripe\Control\Email\SwiftMailer;
use Swift_Mailer;
use Swift_Signers_SMimeSigner;

/**
 * Class SMIMEMailer
 *
 * Mailer that securely encrypts and signs emails
 */
class SMIMEMailer extends SwiftMailer
{
    /**
     * @var array
     */
    private static $dependencies = [
        'SwiftMailer' => '%$' . Swift_Mailer::class,
        'SMimeSigner' => '%$' . Swift_Signers_SMimeSigner::class,
    ];

    /**
     * @var array|string|null $encryptingCerts
     */
    protected $encryptingCerts;

    /**
     * @var string|null $signingCert
     */
    protected $signingCert;

    /**
     * @var string|null $signingKey
     */
    protected $signingKey;

    /**
     * @var array|null $options
     */
    protected $options;

    /**
     * @var array|null $default_options
     */
    private static $default_options = [];

    /**
     * SMIMEMailer constructor.
     *
     * @param array|string|null $encryptingCerts String of a single path to an encrypting cert or array of paths to
     *                                           encrypting certificates, array can be associative where the key is the
     *                                           recipient email address matching the cert (recipient)
     * @param string|null $signingCert Path to signing certificate (sender)
     * @param string|null $signingKey Path to signing private key (sender)
     * @param string|null $signingKeyPassphrase Signing private key passphrase (sender)
     * @param array $options
     *
     * @return void
     */
    public function __construct(
        $encryptingCerts = null,
        ?string $signingCert = null,
        ?string $signingKey = null,
        ?string $signingKeyPassphrase = null,
        array $options = []
    ) {
        parent::__construct();

        $this->setEncryptingCerts($encryptingCerts);
        $this->setSigningCert($signingCert);
        $this->setSigningKey(
            $signingKey,
            $signingKeyPassphrase
        );
        $this->setSwiftSignerOptions($options);
    }

    /**
     * Set options for Swift_Signers_SMimeSigner.
     *
     * Some options are always overridden if environment variables are present. This allows for ease of set up in
     * testing environments, providing assurance of settings.
     *
     * @param array $options Option set. {@see openssl_pkcs7_sign} for available flags
     *
     * @return $this
     */
    public function setSwiftSignerOptions(array $options = []): self
    {
        $options = $options ?: $this->config()->get('default_options');

        $this->options = $options;

        return $this;
    }

    /**
     * Sets the encryption certificates for this mailer.
     *
     * @param array|string|null $encryptingCerts String of a single path to an encrypting cert or array of paths to
     *                                           encrypting certificates, array can be associative where the key is the
     *                                           recipient email address matching the cert (recipient)
     *
     * @return $this
     * @see Swift_Signers_SMimeSigner::setEncryptCertificate()
     */
    public function setEncryptingCerts($encryptingCerts = null): self
    {
        $this->encryptingCerts = $encryptingCerts;
        return $this;
    }

    /**
     * Sets the signing certificate for this mailer.
     *
     * @param string|null $signingCert
     *
     * @return $this
     * @see Swift_Signers_SMimeSigner::setSignCertificate()
     */
    public function setSigningCert(?string $signingCert = null): self
    {
        $this->signingCert = $signingCert;
        return $this;
    }

    /**
     * Sets the signing key along with optional signing key passphrase for this mailer.
     *
     * @param string|null $signingKey
     * @param string|null $signingKeyPassphrase
     *
     * @return $this
     * @see Swift_Signers_SMimeSigner::setSignCertificate()
     */
    public function setSigningKey(?string $signingKey = null, ?string $signingKeyPassphrase = null): self
    {
        // Set passphrase to a blank string if it is null
        $passphrase = $signingKeyPassphrase ?:  '';

        // Assign as array
        $this->signingKey = [
            $signingKey,
            $passphrase
        ];

        return $this;
    }

    /**
     * @param Email $message
     *
     * @return bool Whether the sending was "successful" or not
     * @see Mailer::send()
     */
    public function send($message): bool
    {
        // Get swift message from Email
        $swiftMessage = $message->getSwiftMessage();

        // Create our S/MIME signer
        $sMimeSigner = new Swift_Signers_SMimeSigner();

        // Add our signing certificate, key, and password
        if ($this->signingCert) {
            $sMimeSigner->setSignCertificate($this->signingCert, $this->signingKey);
        }

        // Add our encrypting certificate
        if ($this->encryptingCerts) {
            $sMimeSigner->setEncryptCertificate($this->encryptingCerts);
        }

        // Attach the signer to our message
        $swiftMessage->attachSigner($sMimeSigner);

        // Send message, returns number of successful recipients
        $result = $this->sendSwift($swiftMessage, $failedRecipients);

        // Register any failed recipients
        $message->setFailedRecipients($failedRecipients);

        // The 0 number of successful recipients indicates failure
        return $result !== 0;
    }
}

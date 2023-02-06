<?php

namespace SilverStripe\SMIME\Tests\Control;

use PHPUnit\Framework\MockObject\MockObject;
use SilverStripe\Control\Email\Email;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\SMIME\Control\SMIMEMailer;
use Swift_ByteStream_FileByteStream;
use Throwable;

/**
 * Class SMIMEMailerTest
 *
 * Set of tests to validate the SMIMEMailer class.
 *
 * Note that within the test framework the send email function is intercepted and so we can't test the actual
 * send function. What we are validating is that a {@see Swift_Message}, with expected encryption/signing
 * properties, is passed to the sendSwift function (by mocking the function). We call toString and toByteStream
 * functions on the message that applies the relevant encryption and signing prior to returning a value. With this
 * value we can inspect/assert the expected content.
 */
class SMIMEMailerTest extends SapphireTest
{

    protected $usesDatabase = false; // phpcs:ignore

    /**
     * Asset path for the test recipient crt file
     */
    private static string $recipientCertificateAsset = '/assets/smime_test_recipient.crt';

    /**
     * Asset path for the test recipient private key file, used for testing decryption
     */
    private static string $recipientKeyAsset = '/assets/smime_test_recipient.key';

    /**
     * Asset path for the test sender crt file, used for testing signing of the email.
     */
    private static string $senderCertificateAsset = '/assets/smime_test_sender.crt';

    /**
     * Asset path for the test sender key file, used for testing signing of the email.
     */
    private static string $senderKeyAsset = '/assets/smime_test_sender.key';

    /**
     * Signing password for the test encryption key.
     */
    private static string $senderKeyPassword = 'Test123!';

    /**
     * Pass in an encryption certificate to the SMIMEMailer and check that the email content is encrypted.
     */
    public function testEncryptionOnly(): void
    {
        $unencrytpedContent = 'This is a confidential email.';
        $recipientEncryptionCrt = $this->getAsset(self::$recipientCertificateAsset);
        $email = $this->buildEmail('Email with encryption', $unencrytpedContent);
        $partialMockMailer = $this->createPartialMockedMIMEMailer([$recipientEncryptionCrt]);

        $partialMockMailer->expects($this->once())->method('sendSwift')->with(
            self::callback(function ($message) use ($unencrytpedContent) {
                $encryptedMessage = $message->toString();
                self::assertStringContainsString('Content-Type: application/x-pkcs7-mime;', $encryptedMessage);
                self::assertStringNotContainsString($unencrytpedContent, $encryptedMessage);

                return true;
            })
        );

        $partialMockMailer->send($email);
    }

    /**
     * Pass in an encryption certificate to the SMIMEMailer and with the encrypted email, we can decrypt it
     * with the matching private key.
     */
    public function testSuccessfulDecryption(): void
    {
        $unencrytpedContent = '<h1>This is a confidential email</h1>';
        $email = $this->buildEmail('Email with encryption', $unencrytpedContent);
        $partialMockMailer = $this->createPartialMockedMIMEMailer([
            $this->getAsset(self::$recipientCertificateAsset),
        ]);

        $partialMockMailer->expects($this->once())->method('sendSwift')->with(
            self::callback(function ($message) use ($unencrytpedContent) {

                // Output email message to file
                $file = @tempnam(__DIR__ . '/tmp', 'smimetest');
                $bs = new Swift_ByteStream_FileByteStream($file, true);
                $message->toByteStream($bs);

                // Use openssl to extract private key, using password
                $privateKey = openssl_pkey_get_private(
                    file_get_contents($this->getAsset(self::$recipientKeyAsset)),
                    self::$senderKeyPassword
                );

                // Decrypt email message
                $decryptedFile = @tempnam(__DIR__ . '/tmp', 'decrypted');
                openssl_cms_decrypt(
                    $file,
                    $decryptedFile,
                    file_get_contents($this->getAsset(self::$recipientCertificateAsset)),
                    $privateKey
                );

                // Check that decrypted file contains expected string
                self::assertStringContainsString(
                    $unencrytpedContent,
                    file_get_contents($decryptedFile)
                );

                return true;
            })
        );

        $partialMockMailer->send($email);
    }

    /**
     * Pass in the signing certificate/key pair for the sender, and check that the email content
     * is signed but not encrypted.
     */
    public function testSigningOnly(): void
    {
        $unencrytpedContent = '<h1>This is not a confidential email.</h1>';
        $recipientSigningCrt = $this->getAsset(self::$senderCertificateAsset);
        $recipientSigningKey = $this->getAsset(self::$senderKeyAsset);
        $email = $this->buildEmail(
            'Email smime signed by sender',
            $unencrytpedContent
        );

        $partialMockMailer = $this->createPartialMockedMIMEMailer([
            null,
            $recipientSigningCrt,
            $recipientSigningKey,
            'Test123!',
        ]);

        $partialMockMailer->expects($this->once())->method('sendSwift')->with(
            self::callback(function ($message) use ($unencrytpedContent) {
                // Convert the message to a string. This has signing applied to it
                $signedMessage = $message->toString();

                self::assertStringContainsString(
                    'Content-Type: application/x-pkcs7-signature; name="smime.p7s"',
                    $signedMessage
                );

                self::assertStringContainsString('This is an S/MIME signed message', $signedMessage);
                self::assertStringContainsString($unencrytpedContent, $signedMessage);

                return true;
            })
        );

        $partialMockMailer->send($email);
    }

    /**
     * Pass in an a signing certificate/key pair (without encryption) and check that the email cannot be signed
     * without the correct signing password.
     */
    public function testSigningErrorWithIncorrectSigningPassword(): void
    {
        $unencrytpedContent = '<h1>This is not a confidential email.</h1>';
        $recipientSigningCrt = $this->getAsset(self::$senderCertificateAsset);
        $recipientSigningKey = $this->getAsset(self::$senderKeyAsset);
        $email = $this->buildEmail(
            'Email smime signed by sender',
            $unencrytpedContent
        );

        $partialMockMailer = $this->createPartialMockedMIMEMailer([
            null,
            $recipientSigningCrt,
            $recipientSigningKey,
            'IncorrectPassword!',
        ]);

        $partialMockMailer->expects($this->once())->method('sendSwift')->with(
            self::callback(function ($message) {
                $exception = null;

                try {
                    // Calling toString encrypts and signs.
                    // Here we expect an exception because of incorrect password
                    $message->toString();
                } catch (Throwable $e) {
                    $exception = $e;
                } finally {
                    self::assertEquals(
                        'openssl_pkcs7_sign(): Error getting private key',
                        $exception->getMessage()
                    );
                }

                return true;
            })
        );

        $partialMockMailer->send($email);
    }

    /**
     * Pass in both signing and encryption certificates and check that the email is correctly encrypted and it
     * indicates that it has been digitally signed.
     */
    public function testSigningAndEncryption(): void
    {
        $unencrytpedContent = '<h1>This is a confidential email.</h1>';
        $recipientEncryptionCrt = $this->getAsset(self::$recipientCertificateAsset);
        $senderSigningCrt = $this->getAsset(self::$senderCertificateAsset);
        $senderSigningKey = $this->getAsset(self::$senderKeyAsset);
        $email = $this->buildEmail(
            'Email encrypted and smime signed by sender',
            $unencrytpedContent
        );

        $partialMockMailer = $this->createPartialMockedMIMEMailer([
            $recipientEncryptionCrt,
            $senderSigningCrt,
            $senderSigningKey,
            'Test123!',
        ]);

        $partialMockMailer->expects($this->once())->method('sendSwift')->with(
            self::callback(function ($message) use ($unencrytpedContent) {
                self::assertStringNotContainsString($unencrytpedContent, $message->toString());

                // Note, messages are signed and then encrypted, so the signing particulars are not seen unencrypted
                self::assertStringNotContainsString(
                    'Content-Type: application/x-pkcs7-signature; name="smime.p7s"',
                    $message
                );

                self::assertStringNotContainsString('This is an S/MIME signed message', $message);

                return true;
            })
        );

        $partialMockMailer->send($email);
    }

    /**
     * These tests don't use the database so this prevents any attempt to close the database.
     * Useful for running tests locally where no database is configured.
     *
     * @return void
     */
    public static function tearDownAfterClass(): void
    {
        // Disable as we don't have any db to reset
    }

    /**
     * Returns an SMIMEMailer instance with the sendSwift method mocked.
     * This allows us to perform assertions on the signed/encrypted message
     * that gets sent to the swift mailer.
     *
     * @param array $args
     * @return MockObject|SMIMEMailer
     */
    private function createPartialMockedMIMEMailer(array $args): MockObject|SMIMEMailer
    {
        return $this->getMockBuilder(SMIMEMailer::class)
            ->setConstructorArgs($args)
            ->setMethods(['sendSwift'])
            ->getMock();
    }

    /**
     * Helper function to build an email for test purposes.
     *
     * @param string|null $subject
     * @param string|null $body
     * @param string|null $recipient
     * @return Email
     */
    private function buildEmail(
        ?string $subject = '',
        ?string $body = '',
        ?string $recipient = 'recipient@example.com'
    ): Email {
        $email = new Email();
        $email->setSubject($subject);
        $email->setBody($body);
        $email->setSender('sender@example.com');
        $email->addTo($recipient);

        return $email;
    }

    /**
     * Helper function to get the full file path to an asset.
     *
     * @param string $filename
     * @return string
     */
    private function getAsset(string $filename): string
    {
        return sprintf('%s%s', __DIR__, $filename);
    }

}

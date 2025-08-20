<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Utils;
use Wizardloong\WhatsAppStreamEncryption\MediaType;
use Wizardloong\WhatsAppStreamEncryption\WhatsAppEncryptingStream;
use Wizardloong\WhatsAppStreamEncryption\WhatsAppDecryptingStream;

/**
 * Integration tests for WhatsApp media encryption and decryption streams.
 * Validates that encrypted and decrypted outputs match sample files.
 */
final class WhatsAppSamplesTest extends TestCase
{
    /**
     * Path to the directory containing sample files.
     * @var string
     */
    private string $samplesDir;

    /**
     * Set up the test environment and sample directory path.
     */
    protected function setUp(): void
    {
        // Path to the sample files directory
        $this->samplesDir = __DIR__ . '/../samples';
    }

    /**
     * Test that decryption of encrypted samples matches the original files.
     *
     * @dataProvider provideSamples
     * @param string $mediaType MediaType enum value
     * @param string $originalFile Filename of original media
     * @param string $encryptedFile Filename of encrypted media
     * @param string $keyFile Filename of media key
     */
    public function testDecryptMatchesOriginal(string $mediaType, string $originalFile, string $encryptedFile, string $keyFile): void
    {
        $original = file_get_contents($this->samplesDir . '/' . $originalFile);
        $encrypted = file_get_contents($this->samplesDir . '/' . $encryptedFile);
        $mediaKey = file_get_contents($this->samplesDir . '/' . $keyFile);

        // Create decrypting stream for the encrypted sample
        $decrypting = new WhatsAppDecryptingStream(Utils::streamFor($encrypted), $mediaKey, $mediaType);

        $decrypted = '';
        // Read decrypted data in chunks to avoid memory overflow
        while (!$decrypting->eof()) {
            $decrypted .= $decrypting->read(8192);
        }

        // Assert that decrypted output matches the original file
        $this->assertSame($original, $decrypted, "Decrypted {$mediaType} does not match original");
    }

    /**
     * Test that encryption of original samples matches the provided encrypted files.
     *
     * @dataProvider provideSamples
     * @param string $mediaType MediaType enum value
     * @param string $originalFile Filename of original media
     * @param string $encryptedFile Filename of encrypted media
     * @param string $keyFile Filename of media key
     */
    public function testEncryptMatchesEncrypted(string $mediaType, string $originalFile, string $encryptedFile, string $keyFile): void
    {
        $original = file_get_contents($this->samplesDir . '/' . $originalFile);
        $expectedEncrypted = file_get_contents($this->samplesDir . '/' . $encryptedFile);
        $mediaKey = file_get_contents($this->samplesDir . '/' . $keyFile);

        // Create encrypting stream for the original sample
        $encrypting = new WhatsAppEncryptingStream(Utils::streamFor($original), $mediaType, $mediaKey);
        $ciphertext = '';
        // Read encrypted data in chunks to avoid memory overflow
        while (!$encrypting->eof()) {
            $ciphertext .= $encrypting->read(8192);
        }

        // Assert that encrypted output matches the sample encrypted file
        $this->assertSame($expectedEncrypted, $ciphertext, "Encrypted {$mediaType} does not match sample");
    }

    /**
     * Test that video sidecar MACs match the sample sidecar file.
     */
    public function testVideoSidecarMatchesSample(): void
    {
        $original = file_get_contents($this->samplesDir . '/VIDEO.original');
        $expectedEncrypted = file_get_contents($this->samplesDir . '/VIDEO.encrypted');
        $expectedSidecar   = file_get_contents($this->samplesDir . '/VIDEO.sidecar');
        $mediaKey = file_get_contents($this->samplesDir . '/VIDEO.key');

        // Create encrypting stream with sidecar generation enabled
        $encrypting = new WhatsAppEncryptingStream(Utils::streamFor($original), MediaType::VIDEO, $mediaKey, true);
        $ciphertext = '';
        // Read encrypted data in larger chunks for video
        while (!$encrypting->eof()) {
            $ciphertext .= $encrypting->read(16384);
        }

        $sidecar = $encrypting->getSidecar();

        // Assert that encrypted output and sidecar match the sample files
        $this->assertSame($expectedEncrypted, $ciphertext, "VIDEO encrypted output mismatch");
        $this->assertSame($expectedSidecar, $sidecar, "VIDEO sidecar mismatch");
    }

    /**
     * Provides sample file sets for parameterized tests.
     * @return array
     */
    public function provideSamples(): array
    {
        return [
            [MediaType::AUDIO, 'AUDIO.original', 'AUDIO.encrypted', 'AUDIO.key'],
            [MediaType::IMAGE, 'IMAGE.original', 'IMAGE.encrypted', 'IMAGE.key'],
            [MediaType::VIDEO, 'VIDEO.original', 'VIDEO.encrypted', 'VIDEO.key'],
        ];
    }
}

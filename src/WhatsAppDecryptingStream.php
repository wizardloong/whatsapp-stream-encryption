<?php
declare(strict_types=1);

namespace Wizardloong\WhatsAppStreamEncryption;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Wizardloong\WhatsAppStreamEncryption\Exceptions\DecryptionException;

/**
 * Stream decorator that validates MAC and decrypts an underlying stream encrypted with WhatsApp algorithm.
 *
 * Security note: we verify MAC before exposing decrypted bytes to the caller. To avoid storing everything in memory
 * we buffer encrypted content into a php://temp stream (which swaps to disk when large).
 *
 * This implementation assumes the encrypted stream contains only ciphertext + 10-byte truncated MAC at end.
 * IV and keys are derived from mediaKey (iv is not read from stream).
 */
final class WhatsAppDecryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const BLOCK_SIZE = 16;
    private const MAC_SIZE = 10;

    private string $iv;
    private string $cipherKey;
    private string $macKey;

    private $hmacContext;
    private bool $macChecked = false;
    private string $expectedTruncatedMac = '';

    // Buffer for encrypted bytes while we verify MAC
    private $encryptedBuffer;
    private $decryptedBuffer = '';
    private bool $finalized = false;
    private int $position = 0;
    private bool $eof = false;

    /**
     * @param StreamInterface $stream stream that yields ciphertext + 10-byte mac at the end
     * @param string $mediaKey 32 bytes
     * @param string $mediaType MediaType::*
     */
    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        $this->stream = $stream;
        $keys = KeyExpander::expand($mediaKey, $mediaType);

        $this->iv = $keys['iv'];
        $this->cipherKey = $keys['cipherKey'];
        $this->macKey = $keys['macKey'];

        $this->hmacContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        if ($this->hmacContext === false) {
            throw new DecryptionException('Failed to initialize HMAC context');
        }
        // HMAC covers iv + enc (enc = ciphertext without trailing MAC), so start with IV
        if (!hash_update($this->hmacContext, $this->iv)) {
            throw new DecryptionException('Failed to update HMAC with IV');
        }

        // encryptedBuffer: php://temp keeps memory small for big files
        $this->encryptedBuffer = fopen('php://temp', 'r+');
        if ($this->encryptedBuffer === false) {
            throw new DecryptionException('Failed to create temporary buffer');
        }
    }

    /**
     * Read decrypted data. This implementation buffers encrypted input until the MAC is verified,
     * then decrypts and exposes plaintext.
     */
    public function read(int $length): string
    {
        if ($length <= 0) {
            return '';
        }
        if ($this->eof) {
            return '';
        }

        // If already finalized (MAC checked and decryption done), serve from decryptedBuffer
        if ($this->finalized) {
            $out = substr($this->decryptedBuffer, 0, $length);
            $this->decryptedBuffer = substr($this->decryptedBuffer, strlen($out));
            $this->position += strlen($out);
            if ($this->decryptedBuffer === '') {
                $this->eof = true;
            }
            return $out;
        }

        // Otherwise, keep reading entire encrypted stream into temporary buffer
        while (!$this->stream->eof()) {
            $chunk = $this->stream->read(32768);
            if ($chunk === '') {
                if ($this->stream->eof()) {
                    break;
                }
                // else continue
            }
            if ($chunk !== '') {
                // write to temp buffer
                $written = fwrite($this->encryptedBuffer, $chunk);
                if ($written === false || $written !== strlen($chunk)) {
                    throw new DecryptionException('Failed to write to encrypted temp buffer');
                }
            }
        }

        // Rewind temp buffer and extract mac trailer
        rewind($this->encryptedBuffer);
        $stat = fstat($this->encryptedBuffer);
        $total = $stat['size'] ?? 0;

        if ($total < self::MAC_SIZE) {
            throw new DecryptionException('Encrypted data too short to contain MAC');
        }

        $ciphertextLen = $total - self::MAC_SIZE;

        // Read ciphertext and update HMAC incrementally
        $remaining = $ciphertextLen;
        $bufSize = 65536;
        while ($remaining > 0) {
            $toRead = min($bufSize, $remaining);
            $chunk = fread($this->encryptedBuffer, $toRead);
            if ($chunk === false) {
                throw new DecryptionException('Failed reading ciphertext from buffer');
            }
            $remaining -= strlen($chunk);
            if (!hash_update($this->hmacContext, $chunk)) {
                throw new DecryptionException('Failed updating HMAC with ciphertext chunk');
            }
        }

        // Read expected/actual mac (last 10 bytes)
        $actualMac = fread($this->encryptedBuffer, self::MAC_SIZE);
        if ($actualMac === false || strlen($actualMac) !== self::MAC_SIZE) {
            throw new DecryptionException('Failed to read MAC from buffer');
        }

        $computedMac = hash_final($this->hmacContext, true);
        if ($computedMac === false) {
            throw new DecryptionException('Failed to finalize HMAC');
        }
        $computedTruncated = substr($computedMac, 0, self::MAC_SIZE);

        // Constant time compare
        if (!hash_equals($computedTruncated, $actualMac)) {
            throw new DecryptionException('MAC mismatch: data may be corrupted or tampered');
        }

        // MAC ok — decrypt ciphertext
        rewind($this->encryptedBuffer);
        $ciphertext = '';
        $remaining = $ciphertextLen;
        while ($remaining > 0) {
            $toRead = min($bufSize, $remaining);
            $chunk = fread($this->encryptedBuffer, $toRead);
            if ($chunk === false) {
                throw new DecryptionException('Failed reading ciphertext for decryption');
            }
            $ciphertext .= $chunk;
            $remaining -= strlen($chunk);
        }

        // Decrypt in one call: use ZERO_PADDING, then remove PKCS#7 manually
        $plainRaw = openssl_decrypt($ciphertext, 'aes-256-cbc', $this->cipherKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        if ($plainRaw === false) {
            throw new DecryptionException('OpenSSL decryption failed');
        }

        // Remove PKCS#7 padding
        $plain = $this->removePkcs7Padding($plainRaw);

        // store plaintext for serving
        $this->decryptedBuffer = $plain;
        $this->finalized = true;

        // serve requested length
        $out = substr($this->decryptedBuffer, 0, $length);
        $this->decryptedBuffer = substr($this->decryptedBuffer, strlen($out));
        $this->position += strlen($out);
        if ($this->decryptedBuffer === '') {
            $this->eof = true;
        }

        // close temp buffer
        fclose($this->encryptedBuffer);
        return $out;
    }

    private function removePkcs7Padding(string $data): string
    {
        $len = strlen($data);
        if ($len === 0) {
            return '';
        }
        $last = ord($data[$len - 1]);
        if ($last < 1 || $last > self::BLOCK_SIZE) {
            throw new DecryptionException('Invalid PKCS#7 padding length');
        }
        // verify padding bytes
        $pad = substr($data, -$last);
        if (strlen($pad) !== $last) {
            throw new DecryptionException('Invalid PKCS#7 padding (short)');
        }
        // constant time check
        $valid = true;
        for ($i = 0; $i < $last; $i++) {
            if (ord($pad[$i]) !== $last) {
                $valid = false;
            }
        }
        if (!$valid) {
            throw new DecryptionException('Invalid PKCS#7 padding bytes');
        }
        return substr($data, 0, $len - $last);
    }

    // PSR-7 minimal implementation
    public function getSize(): ?int { return null; }
    public function tell(): int { return $this->position; }
    public function eof(): bool { return $this->eof; }
    public function isSeekable(): bool { return false; }
    public function seek($offset, $whence = SEEK_SET): void { throw new DecryptionException('Not seekable'); }
    public function rewind(): void { throw new DecryptionException('Not seekable'); }
    public function isWritable(): bool { return false; }
    public function write($string): int { throw new DecryptionException('Not writable'); }
    public function __destruct() { if (is_resource($this->encryptedBuffer)) { fclose($this->encryptedBuffer); } }
}

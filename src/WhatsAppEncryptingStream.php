<?php
declare(strict_types=1);

namespace Wizardloong\WhatsAppStreamEncryption;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Wizardloong\WhatsAppStreamEncryption\Exceptions\EncryptionException;

/**
 * Stream decorator that encrypts an underlying PSR-7 stream using WhatsApp algorithm.
 *
 * Produces ciphertext (iv omitted from output — WhatsApp stores iv separately in sidecar/start bytes).
 * NOTE: If you need to include iv as prefix in output, adapt accordingly. This implementation follows the
 * specification: iv is used for MAC and encryption but sidecar generation keeps IV as first element.
 */
final class WhatsAppEncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const BLOCK_SIZE = 16;
    private const CHUNK_SIZE = 65536; // 64KB
    private const MAC_SIZE = 10;

    private string $iv;
    private string $cipherKey;
    private string $macKey;

    private $hashContext;
    private string $pendingData = '';
    private string $outputBuffer = '';
    private string $trailer = '';
    private bool $finalized = false;
    private int $position = 0;
    private bool $eof = false;

    // Sidecar
    private bool $generateSidecar = false;
    private string $sidecar = '';
    private string $sidecarBuffer = '';

    /**
     * @param StreamInterface $stream source plaintext stream
     * @param string $mediaKey 32 bytes
     * @param string $mediaType MediaType::*
     * @param bool $generateSidecar whether to generate streaming sidecar (64K chunk + 16 overlap)
     */
    public function __construct(StreamInterface $stream, string $mediaType, string $mediaKey = '', bool $generateSidecar = false)
    {
        $this->stream = $stream;
        
        // Generate mediaKey if not provided
        if ($mediaKey === '') {
            // Secure random 32 bytes
            $mediaKey = random_bytes(32);
        }
        
        $keys = KeyExpander::expand($mediaKey, $mediaType);

        $this->iv = $keys['iv'];
        $this->cipherKey = $keys['cipherKey'];
        $this->macKey = $keys['macKey'];

        // Initialize HMAC context by using incremental hashing
        $this->hashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        if ($this->hashContext === false) {
            throw new EncryptionException('Failed to initialize HMAC context');
        }
        // HMAC covers iv + enc; we start by updating with iv
        if (!hash_update($this->hashContext, $this->iv)) {
            throw new EncryptionException('Failed to update HMAC with IV');
        }

        if ($generateSidecar) {
            $this->generateSidecar = true;
            // sidecarBuffer starts with IV (spec expects first chunk to include IV)
            $this->sidecarBuffer = $this->iv;
        }
    }

    /**
     * Read encrypted data: streaming encryption with manual PKCS#7 padding at finalize.
     * read() may return any number of bytes up to $length.
     */
    public function read(int $length): string
    {
        if ($length <= 0) {
            return '';
        }

        if ($this->eof) {
            return '';
        }

        $out = $this->outputBuffer;
        $this->outputBuffer = '';

        while (strlen($out) < $length) {
            if (!$this->finalized) {
                // Try to fill pendingData from source
                $need = max(8192, $length - strlen($out));
                $chunk = $this->stream->read($need);

                if ($chunk !== '') {
                    $this->pendingData .= $chunk;

                    // Process all but last BLOCK_SIZE bytes to keep ability to pad at end
                    $processable = intdiv(max(0, strlen($this->pendingData) - self::BLOCK_SIZE), self::BLOCK_SIZE) * self::BLOCK_SIZE;
                    if ($processable > 0) {
                        $toEncrypt = substr($this->pendingData, 0, $processable);
                        $this->pendingData = substr($this->pendingData, $processable);

                        $encrypted = $this->encryptBlocks($toEncrypt);
                        $out .= $encrypted;
                    }
                    continue;
                }

                // EOF on source: finalize (pad + encrypt)
                if ($this->stream->eof()) {
                    $out .= $this->finalizeEncryption();
                    // After finalize, continue to supply the trailer (MAC)
                } else {
                    // nothing available now
                    break;
                }
            } else {
                // finalized - emit trailer bytes (MAC truncated)
                if ($this->trailer !== '') {
                    $need = $length - strlen($out);
                    $take = substr($this->trailer, 0, $need);
                    $out .= $take;
                    $this->trailer = substr($this->trailer, strlen($take));
                    if ($this->trailer === '') {
                        $this->eof = true;
                    }
                    break;
                } else {
                    $this->eof = true;
                    break;
                }
            }
        }

        // If we produced more than requested, keep rest
        if (strlen($out) > $length) {
            $this->outputBuffer = substr($out, $length);
            $out = substr($out, 0, $length);
        }

        $this->position += strlen($out);
        return $out;
    }

    /**
     * Encrypt blocks (length multiple of BLOCK_SIZE). Updates IV to last ciphertext block.
     */
    private function encryptBlocks(string $data): string
    {
        if ($data === '') {
            return '';
        }
        if ((strlen($data) % self::BLOCK_SIZE) !== 0) {
            throw new EncryptionException('encryptBlocks expects multiple-of-block-size data');
        }

        $cipher = 'aes-256-cbc';
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;

        $ciphertext = openssl_encrypt($data, $cipher, $this->cipherKey, $options, $this->iv);
        if ($ciphertext === false) {
            throw new EncryptionException('OpenSSL encryption failed');
        }

        // update IV to last block of ciphertext
        $this->iv = substr($ciphertext, -self::BLOCK_SIZE);

        // update HMAC with ciphertext
        if (!hash_update($this->hashContext, $ciphertext)) {
            throw new EncryptionException('Failed to update HMAC with ciphertext');
        }

        // update sidecar generation
        $this->appendToSidecar($ciphertext);

        return $ciphertext;
    }

    /**
     * Finalize: pad pendingData (PKCS#7), encrypt, finalize HMAC and build trailer.
     */
    private function finalizeEncryption(): string
    {
        if ($this->finalized) {
            return '';
        }

        $processed = '';

        $padLen = self::BLOCK_SIZE - (strlen($this->pendingData) % self::BLOCK_SIZE);
        if ($padLen === 0) {
            $padLen = self::BLOCK_SIZE;
        }
        $this->pendingData .= str_repeat(chr($padLen), $padLen);

        if ($this->pendingData !== '') {
            if ((strlen($this->pendingData) % self::BLOCK_SIZE) !== 0) {
                throw new EncryptionException('Final pendingData length not multiple of block size after padding');
            }
            $encrypted = $this->encryptBlocks($this->pendingData);
            $processed .= $encrypted;
            $this->pendingData = '';
        }

        // Finalize HMAC and create trailer (truncated)
        $mac = hash_final($this->hashContext, true);
        if ($mac === false) {
            throw new EncryptionException('Failed to finalize HMAC');
        }
        $this->trailer = substr($mac, 0, self::MAC_SIZE);

        // Now include the mac in sidecar if generating
        if ($this->generateSidecar) {
            $this->sidecarBuffer .= $this->trailer;
            // Process any new full chunks that might form after appending mac (unlikely, but for edge cases where remaining +10 >= CHUNK_SIZE + BLOCK_SIZE)
            $this->appendToSidecar('');
            $this->finalizeSidecar();
        }

        $this->finalized = true;
        return $processed;
    }

    /**
     * Sidecar helpers: accumulate encrypted bytes and produce truncated HMACs for each chunk.
     */
    private function appendToSidecar(string $encryptedData): void
    {
        if (!$this->generateSidecar || $encryptedData === '') {
            return;
        }

        $this->sidecarBuffer .= $encryptedData;

        $required = self::CHUNK_SIZE + self::BLOCK_SIZE;
        while (strlen($this->sidecarBuffer) >= $required) {
            $chunk = substr($this->sidecarBuffer, 0, $required);

            $mac = hash_hmac('sha256', $chunk, $this->macKey, true);
            if ($mac === false) {
                throw new EncryptionException('Failed to compute sidecar HMAC');
            }
            $this->sidecar .= substr($mac, 0, self::MAC_SIZE);

            // remove CHUNK_SIZE bytes, keep last BLOCK_SIZE overlap
            $this->sidecarBuffer = substr($this->sidecarBuffer, self::CHUNK_SIZE);
        }
    }

    private function finalizeSidecar(): void
    {
        if ($this->sidecarBuffer === '') {
            return;
        }
        if (strlen($this->sidecarBuffer) > self::BLOCK_SIZE) {  // Only if >16B (partial enc present)
            $mac = hash_hmac('sha256', $this->sidecarBuffer, $this->macKey, true);
            if ($mac === false) {
                throw new EncryptionException('Failed to compute final sidecar HMAC');
            }
            $this->sidecar .= substr($mac, 0, self::MAC_SIZE);
        }
        $this->sidecarBuffer = '';
    }

    public function getSidecar(): string
    {
        if (!$this->finalized) {
            throw new EncryptionException('Stream must be fully read/finalized before getting sidecar');
        }
        return $this->sidecar;
    }

    // PSR-7 StreamInterface basic impls
    public function getSize(): ?int { return null; }
    public function tell(): int { return $this->position; }
    public function eof(): bool { return $this->eof; }
    public function isSeekable(): bool { return false; }
    public function seek($offset, $whence = SEEK_SET): void { throw new EncryptionException('Not seekable'); }
    public function rewind(): void { throw new EncryptionException('Not seekable'); }
    public function isWritable(): bool { return false; }
    public function write($string): int { throw new EncryptionException('Not writable'); }
    public function __destruct() { /* nothing to free */ }
}

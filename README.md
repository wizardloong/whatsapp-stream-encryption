# WhatsApp Media Encryption/Decryption PHP Library

## Overview
This PHP library provides tools for encrypting and decrypting WhatsApp media files (images, audio, video) using the official WhatsApp algorithm. It supports streaming encryption/decryption, MAC validation, and sidecar generation for video integrity.

- **Encryption**: AES-256-ECB with CBC-like chaining and PKCS#7 padding.
- **Decryption**: Validates MAC, removes padding, and restores original media.
- **Sidecar**: Generates chunked MACs for video files (used by WhatsApp for integrity checks).
- **Streaming**: Works with PSR-7 streams for efficient memory usage.

## Features
- Compatible with WhatsApp's official media encryption format
- Handles large files efficiently (streaming, chunked processing)
- Validates MAC for data integrity
- Generates sidecar MACs for video
- Custom exceptions for robust error handling
- Fully tested with PHPUnit and sample files

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/wizardloong/whatsapp-stream-encryption
cd whatsapp-stream-encryption
composer install
```

## Usage

### Encrypting Media
```php
use Wizardloong\WhatsAppStreamEncryption\WhatsAppEncryptingStream;
use Wizardloong\WhatsAppStreamEncryption\MediaType;
use GuzzleHttp\Psr7\Utils;

$mediaKey = random_bytes(32); // Or use WhatsApp-provided key
$stream = Utils::streamFor(fopen('input.jpg', 'rb'));
$encrypting = new WhatsAppEncryptingStream($stream, $mediaKey, MediaType::IMAGE);

$output = '';
while (!$encrypting->eof()) {
	$output .= $encrypting->read(8192);
}
file_put_contents('output.encrypted', $output);
```

### Decrypting Media
```php
use Wizardloong\WhatsAppStreamEncryption\WhatsAppDecryptingStream;
use Wizardloong\WhatsAppStreamEncryption\MediaType;
use GuzzleHttp\Psr7\Utils;

$mediaKey = file_get_contents('IMAGE.key');
$stream = Utils::streamFor(fopen('output.encrypted', 'rb'));
$decrypting = new WhatsAppDecryptingStream($stream, $mediaKey, MediaType::IMAGE);

$decrypted = '';
while (!$decrypting->eof()) {
	$decrypted .= $decrypting->read(8192);
}
file_put_contents('output.decrypted.jpg', $decrypted);
```

### Video Sidecar Generation
```php
$encrypting = new WhatsAppEncryptingStream($stream, $mediaKey, MediaType::VIDEO, true);
while (!$encrypting->eof()) {
	$ciphertext .= $encrypting->read(16384);
}
$sidecar = $encrypting->getSidecar();
file_put_contents('output.sidecar', $sidecar);
```

## Running Tests

Tests use PHPUnit and sample files in the `samples/` directory.

```bash
make test
# or
vendor/bin/phpunit --testdox
```

## Specifications

- **Key Expansion**: Uses HKDF-SHA256 to derive IV, cipherKey, and macKey from mediaKey and mediaType.
- **Encryption**: AES-256-ECB, CBC-like chaining (XOR with previous block), PKCS#7 padding.
- **MAC**: HMAC-SHA256 over IV + ciphertext, first 10 bytes appended as trailer.
- **Sidecar (video)**: HMAC-SHA256 over each 64KB chunk + 16-byte overlap, first 10 bytes per chunk.
- **Decryption**: Validates MAC, removes PKCS#7 padding, restores original data.
- **Exceptions**: Throws custom exceptions for encryption/decryption errors.

## File Structure

- `src/WhatsAppEncryptingStream.php` — Streaming encryption implementation
- `src/WhatsAppDecryptingStream.php` — Streaming decryption implementation
- `src/KeyExpander.php` — Key derivation logic
- `src/MediaType.php` — Media type enum
- `src/Exceptions/EncryptionException.php` — Encryption error class
- `src/Exceptions/DecryptionException.php` — Decryption error class
- `tests/WhatsAppSamplesTest.php` — Integration tests
- `samples/` — Sample media, keys, and expected outputs

## Error Handling
- Throws `EncryptionException` for encryption failures (OpenSSL, padding, etc.)
- Throws `DecryptionException` for decryption failures (MAC, padding, etc.)

## Notes
- Always use chunked reading/writing for large files to avoid memory issues.
- MediaKey must be 32 bytes (random or WhatsApp-provided).
- Sidecar is only needed for video integrity checks.

## License
MIT

## Authors
- Victor Miroliubov w.izard@outlook.com

## Contributing
Pull requests and issues are welcome!

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

First, install the package via Composer in your project:

```bash
composer require wizardloong/whatsapp-stream-encryption
```

Then use it in your code:

### Encrypting Media
```php
require 'vendor/autoload.php';

use Wizardloong\WhatsAppStreamEncryption\WhatsAppEncryptingStream;
use Wizardloong\WhatsAppStreamEncryption\MediaType;
use GuzzleHttp\Psr7\Utils;

$mediaKey = random_bytes(32); // Or use WhatsApp-provided key
$inputStream = Utils::streamFor(fopen('input.jpg', 'rb'));
$encrypting = new WhatsAppEncryptingStream($inputStream, MediaType::IMAGE, $mediaKey);

$outputStream = fopen('output.encrypted', 'wb');
while (!$encrypting->eof()) {
	fwrite($outputStream, $encrypting->read(8192));
}
fclose($outputStream);
```

### Decrypting Media
```php
require 'vendor/autoload.php';

use Wizardloong\WhatsAppStreamEncryption\WhatsAppDecryptingStream;
use Wizardloong\WhatsAppStreamEncryption\MediaType;
use GuzzleHttp\Psr7\Utils;

$mediaKey = file_get_contents('IMAGE.key');
$encryptedStream = Utils::streamFor(fopen('output.encrypted', 'rb'));
$decrypting = new WhatsAppDecryptingStream($encryptedStream, MediaType::IMAGE, mediaKey);

$outputStream = fopen('output.decrypted.jpg', 'wb');
while (!$decrypting->eof()) {
	fwrite($outputStream, $decrypting->read(8192));
}
fclose($outputStream);
```

### Video Sidecar Generation
```php
require 'vendor/autoload.php';

use Wizardloong\WhatsAppStreamEncryption\WhatsAppEncryptingStream;
use Wizardloong\WhatsAppStreamEncryption\MediaType;
use GuzzleHttp\Psr7\Utils;

$mediaKey = file_get_contents('VIDEO.key');
$inputStream = Utils::streamFor(fopen('input.mp4', 'rb'));
$encrypting = new WhatsAppEncryptingStream($inputStream, $mediaKey, MediaType::VIDEO, true);

$outputStream = fopen('output.encrypted', 'wb');
while (!$encrypting->eof()) {
	fwrite($outputStream, $encrypting->read(16384));
}
fclose($outputStream);

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

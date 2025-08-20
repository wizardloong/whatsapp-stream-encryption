<?php
namespace Wizardloong\WhatsAppStreamEncryption\Exceptions;

use RuntimeException;

/**
 * Exception thrown when an encryption error occurs in WhatsAppStreamEncryption.
 * Use this for all encryption-related failures (e.g., OpenSSL errors, padding issues).
 */
final class EncryptionException extends RuntimeException
{
	// Custom encryption exception for WhatsApp media encryption errors
}

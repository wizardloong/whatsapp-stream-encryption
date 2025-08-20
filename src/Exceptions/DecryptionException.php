<?php
namespace Wizardloong\WhatsAppStreamEncryption\Exceptions;

use RuntimeException;

/**
 * Exception thrown when a decryption error occurs in WhatsAppStreamEncryption.
 * Use this for all decryption-related failures (e.g., MAC validation, padding errors).
 */
final class DecryptionException extends RuntimeException
{
	// Custom decryption exception for WhatsApp media decryption errors
}

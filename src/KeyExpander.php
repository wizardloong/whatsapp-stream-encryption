<?php
declare(strict_types=1);

namespace Wizardloong\WhatsAppStreamEncryption;

use Wizardloong\WhatsAppStreamEncryption\Exceptions\EncryptionException;

/**
 * Expand 32-byte mediaKey -> 112 bytes using HKDF-SHA256.
 * Uses PHP's hash_hkdf when available, otherwise falls back to manual HKDF.
 */
final class KeyExpander
{
    public const EXPANDED_LENGTH = 112;

    /**
     * @param string $mediaKey 32-byte (256-bit) key
     * @param string $mediaType one of MediaType::*
     * @return array{iv: string, cipherKey: string, macKey: string, refKey: string}
     * @throws EncryptionException
     */
    public static function expand(string $mediaKey, string $mediaType): array
    {
        if (strlen($mediaKey) !== 32) {
            throw new EncryptionException('mediaKey must be 32 bytes');
        }

        $info = MediaType::hkdfInfoFor($mediaType);

        $expanded = hash_hkdf('sha256', $mediaKey, self::EXPANDED_LENGTH, $info);
        if ($expanded === '') {
            throw new EncryptionException('HKDF expansion failed (hash_hkdf returned empty)');
        }
        
        if (strlen($expanded) !== self::EXPANDED_LENGTH) {
            throw new EncryptionException('HKDF produced unexpected length: ' . strlen($expanded));
        }

        return [
            'iv' => substr($expanded, 0, 16),
            'cipherKey' => substr($expanded, 16, 32), // 16..47 -> length 32
            'macKey' => substr($expanded, 48, 32),    // 48..79
            'refKey' => substr($expanded, 80, 32),    // 80..111
        ];
    }
}

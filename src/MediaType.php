<?php
declare(strict_types=1);

namespace Wizardloong\WhatsAppStreamEncryption;

/**
 * Simple media type holder (could be enum in PHP 8.1+)
 */
final class MediaType
{
    public const IMAGE = 'IMAGE';
    public const VIDEO = 'VIDEO';
    public const AUDIO = 'AUDIO';
    public const DOCUMENT = 'DOCUMENT';

    public static function hkdfInfoFor(string $type): string
    {
        return match ($type) {
            self::IMAGE => 'WhatsApp Image Keys',
            self::VIDEO => 'WhatsApp Video Keys',
            self::AUDIO => 'WhatsApp Audio Keys',
            self::DOCUMENT => 'WhatsApp Document Keys',
            default => throw new \InvalidArgumentException('Unknown media type ' . $type),
        };
    }
}

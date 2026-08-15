<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp;

use Zappzarapp\Security\Totp\Exception\InvalidProvisioningDataException;

/**
 * otpauth:// provisioning URI for authenticator app enrollment
 *
 * Produces the Key Uri Format understood by all common authenticator
 * apps: otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=...
 * &digits=...&period=...
 *
 * The URI contains the shared secret - treat its string form (and any
 * QR code rendered from it) as secret material: show it once during
 * enrollment, never log or store it.
 *
 * ## Usage
 *
 * ```php
 * $uri = new ProvisioningUri('Example App', 'marc@example.com', $secret);
 * $qrPayload = $uri->toString();
 * ```
 */
final readonly class ProvisioningUri
{
    /**
     * @param string $issuer Service name shown in the authenticator app
     * @param string $accountName User-identifying label (e-mail, username)
     * @param TotpSecret $secret The shared secret to provision
     * @param TotpConfig $config Code parameters to advertise
     *
     * @throws InvalidProvisioningDataException If issuer or account name are invalid
     */
    public function __construct(
        private string $issuer,
        private string $accountName,
        private TotpSecret $secret,
        private TotpConfig $config = new TotpConfig(),
    ) {
        $this->assertLabelComponent('issuer', $this->issuer);
        $this->assertLabelComponent('account name', $this->accountName);
    }

    /**
     * Get the otpauth:// URI string
     */
    public function toString(): string
    {
        $label = rawurlencode($this->issuer) . ':' . rawurlencode($this->accountName);

        $parameters = http_build_query([
            'secret'    => $this->secret->toBase32(),
            'issuer'    => $this->issuer,
            'algorithm' => $this->config->algorithm->value,
            'digits'    => $this->config->digits,
            'period'    => $this->config->period,
        ], '', '&', PHP_QUERY_RFC3986);

        return 'otpauth://totp/' . $label . '?' . $parameters;
    }

    /**
     * Reject empty values, control characters, and the label delimiter
     *
     * The Key Uri Format forbids colons in both label components - the
     * colon separates issuer and account name.
     *
     * @throws InvalidProvisioningDataException If the component is invalid
     */
    private function assertLabelComponent(string $field, string $value): void
    {
        if ($value === '') {
            throw InvalidProvisioningDataException::empty($field);
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw InvalidProvisioningDataException::controlCharacters($field);
        }

        if (str_contains($value, ':')) {
            throw InvalidProvisioningDataException::containsColon($field);
        }
    }
}

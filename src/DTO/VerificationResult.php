<?php

namespace BasicXII\CloudSecurity\DTO;

final class VerificationResult
{
    /** @param array{authentication: string, source_ip: string, domain: string, signing: string} $checks */
    public function __construct(public readonly string $projectId, public readonly string $projectName, public readonly array $checks) {}

    public function allowed(): bool
    {
        return true;
    }
}

<?php

namespace BasicXII\CloudSecurity\Scanner;

class FlowValue
{
    /** @param list<string> $sources
     * @param  list<string>  $encoders
     */
    public function __construct(
        public array $sources = [],
        public array $encoders = [],
        public ?string $literal = null,
        public bool $uncertain = false,
        public bool $request = false,
    ) {}

    public function merge(self $other): self
    {
        return new self(array_values(array_unique([...$this->sources, ...$other->sources])),
            array_slice([...$this->encoders, ...$other->encoders], 0, 8), null,
            $this->uncertain || $other->uncertain, $this->request || $other->request);
    }
}

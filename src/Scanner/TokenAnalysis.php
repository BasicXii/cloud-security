<?php

namespace BasicXII\CloudSecurity\Scanner;

use PhpToken;
use RuntimeException;

class TokenAnalysis
{
    /** @var list<PhpToken> */
    private array $tokens;

    /** @var array<int, int> */
    private array $pairs = [];

    /** @var array<string, array<string, mixed>> */
    private array $findings = [];

    private int $work = 0;

    /** @var list<string> */
    private array $requestTypes = ['illuminate\\http\\request'];

    /** @var list<string> */
    private array $requestFacades = ['illuminate\\support\\facades\\request'];

    public function __construct(string $source)
    {
        $this->tokens = array_values(array_filter(PhpToken::tokenize($source), fn (PhpToken $token) => ! $token->is([T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG, T_CLOSE_TAG, T_INLINE_HTML, T_ENCAPSED_AND_WHITESPACE, T_START_HEREDOC, T_END_HEREDOC])));
        if (count($this->tokens) > 100000) {
            throw new RuntimeException('PHP analysis token limit exceeded.');
        }
        $stack = [];
        foreach ($this->tokens as $index => $token) {
            if (in_array($token->text, ['(', '[', '{', '#['], true)) {
                $stack[] = $index;
            } elseif (in_array($token->text, [')', ']', '}'], true)) {
                $start = array_pop($stack);
                if ($start === null || ['(' => ')', '[' => ']', '{' => '}', '#[' => ']'][$this->tokens[$start]->text] !== $token->text) {
                    throw new RuntimeException('PHP analysis encountered unbalanced syntax.');
                }
                $this->pairs[$start] = $index;
            }
            if ($token->id === T_USE) {
                $import = strtolower(ltrim($this->tokens[$index + 1]->text ?? '', '\\'));
                $alias = ($this->tokens[$index + 2]->id ?? null) === T_AS ? strtolower($this->tokens[$index + 3]->text ?? '') : 'request';
                if ($import === 'illuminate\\http\\request') {
                    $this->requestTypes[] = $alias;
                } elseif ($import === 'illuminate\\support\\facades\\request') {
                    $this->requestFacades[] = $alias;
                }
            }
        }
        if ($stack !== []) {
            throw new RuntimeException('PHP analysis encountered unbalanced syntax.');
        }
    }

    /** @return list<array<string, mixed>> */
    public function analyze(): array
    {
        $variables = [];
        $this->walk(0, count($this->tokens), $variables);
        $long = 0;
        $escapes = 0;
        $characters = 0;
        foreach ($this->tokens as $index => $token) {
            if ($token->id === T_CONSTANT_ENCAPSED_STRING) {
                if (strlen($token->text) >= 1024 && preg_match('/[A-Za-z0-9+\/=]{1024}|[a-f0-9]{1024}/i', $token->text)) {
                    $long = $token->line;
                }
                if (substr_count($token->text, '\\x') + preg_match_all('/\\\\[0-7]{2,3}/', $token->text) >= 16) {
                    $escapes = $token->line;
                }
            }
            if ($token->id === T_STRING && strtolower($token->text) === 'chr' && ($this->tokens[$index + 1]->text ?? '') === '(') {
                $characters++;
            }
        }
        $signals = [];
        if ($long) {
            $signals[] = 'long_encoded_string';
        }
        if ($escapes) {
            $signals[] = 'excessive_escaping';
        }
        if ($characters >= 8) {
            $signals[] = 'chr_chain';
        }
        if ($signals !== []) {
            $this->add('PHP-OBFUSCATION', $long ?: ($escapes ?: 1), $signals, new FlowValue, null, 'low');
        }

        return array_values($this->findings);
    }

    /** @param array<string, FlowValue> $variables */
    private function walk(int $start, int $end, array &$variables, int $depth = 0): void
    {
        $this->budget($depth);
        for ($i = $start; $i < $end; $i++) {
            $token = $this->tokens[$i];
            if ($token->id === T_FUNCTION) {
                if (($this->tokens[$i - 1]->id ?? null) === T_USE) {
                    while ($i < $end && $this->tokens[$i]->text !== ';') {
                        $i++;
                    }

                    continue;
                }
                $open = $i + 1;
                while ($open < $end && $this->tokens[$open]->text !== '(') {
                    $open++;
                }
                $close = $this->pairs[$open] ?? $end;
                $body = $close + 1;
                $local = [];
                for ($p = $open + 1; $p < $close; $p++) {
                    if ($this->tokens[$p]->id === T_VARIABLE) {
                        $type = strtolower(ltrim($this->tokens[$p - 1]->text, '\\'));
                        $local[$this->tokens[$p]->text] = new FlowValue(request: in_array($type, $this->requestTypes, true));
                    }
                }
                if (($this->tokens[$body]->id ?? null) === T_USE) {
                    $captureEnd = $this->pairs[$body + 1] ?? $body;
                    for ($p = $body + 2; $p < $captureEnd; $p++) {
                        $name = $this->tokens[$p]->text;
                        if (isset($variables[$name]) && ! isset($local[$name])) {
                            $local[$name] = $variables[$name];
                        }
                    }
                    $body = $captureEnd + 1;
                }
                while ($body < $end && ! in_array($this->tokens[$body]->text, ['{', ';'], true)) {
                    $body++;
                }
                if (($this->tokens[$body]->text ?? '') === '{') {
                    $finish = $this->pairs[$body];
                    $this->walk($body + 1, $finish, $local, $depth + 1);
                    $i = $finish;
                } else {
                    $i = $body;
                }

                continue;
            }
            if ($token->text === '{') {
                $branch = $variables;
                $this->walk($i + 1, $this->pairs[$i], $branch, $depth + 1);
                foreach ($branch as $name => $value) {
                    $merged = ($variables[$name] ?? new FlowValue)->merge($value);
                    $merged->uncertain = true;
                    $variables[$name] = $merged;
                }
                $i = $this->pairs[$i];

                continue;
            }
            $finish = $i;
            while ($finish < $end && ! in_array($this->tokens[$finish]->text, [';', '{'], true) && $this->tokens[$finish]->id !== T_FUNCTION) {
                if (isset($this->pairs[$finish]) && $this->tokens[$finish]->text !== '{') {
                    $finish = $this->pairs[$finish];
                }
                $finish++;
            }
            $this->expression($i, $finish, $variables, $depth + 1);
            $i = $finish - 1;
            if (($this->tokens[$finish]->text ?? '') === ';') {
                $i++;
            }
        }
    }

    /** @param array<string, FlowValue> $variables */
    private function expression(int $start, int $end, array &$variables, int $depth): FlowValue
    {
        $this->budget($depth);
        if ($start >= $end) {
            return new FlowValue;
        }
        if ($this->tokens[$start]->id === T_FUNCTION) {
            $local = $variables;
            $this->walk($start, $end, $local, $depth + 1);

            return new FlowValue;
        }
        if ($this->tokens[$start]->id === T_FN && ($this->tokens[$start + 1]->text ?? '') === '(') {
            $close = $this->pairs[$start + 1];
            $local = $variables;
            for ($p = $start + 2; $p < $close; $p++) {
                if ($this->tokens[$p]->id === T_VARIABLE) {
                    $local[$this->tokens[$p]->text] = new FlowValue;
                }
            }
            $body = $close + 1;
            while ($body < $end && $this->tokens[$body]->id !== T_DOUBLE_ARROW) {
                $body++;
            }
            $this->expression($body + 1, $end, $local, $depth + 1);

            return new FlowValue;
        }
        if ($this->tokens[$start]->id === T_VARIABLE && in_array($this->tokens[$start + 1]->text ?? '', ['=', '.='], true)) {
            $value = $this->expression($start + 2, $end, $variables, $depth + 1);
            $name = $this->tokens[$start]->text;
            if ($this->tokens[$start + 1]->text === '.=') {
                $value = ($variables[$name] ?? new FlowValue)->merge($value);
            }
            $variables[$name] = $value;

            return $value;
        }
        $result = new FlowValue;
        $literal = '';
        $literalOnly = true;
        for ($i = $start; $i < $end; $i++) {
            $this->budget($depth);
            $token = $this->tokens[$i];
            $value = new FlowValue;
            $name = null;
            $dynamic = false;
            if ($token->id === T_VARIABLE) {
                $source = substr($token->text, 1);
                $value = in_array($source, RiskScorer::SOURCES, true) ? new FlowValue([$source]) : ($variables[$token->text] ?? new FlowValue);
                $name = $value->literal;
                $dynamic = true;
                while (($this->tokens[$i + 1]->text ?? '') === '[') {
                    $subscript = $this->expression($i + 2, $this->pairs[$i + 1], $variables, $depth + 1);
                    $value = $value->merge($subscript);
                    $i = $this->pairs[$i + 1];
                    $name = null;
                }
            } elseif ($token->id === T_CONSTANT_ENCAPSED_STRING) {
                $value->literal = strlen($token->text) <= 256 ? ($token->text[0] === '"'
                    ? stripcslashes(substr($token->text, 1, -1)) : str_replace(["\\'", '\\\\'], ["'", '\\'], substr($token->text, 1, -1))) : null;
            } elseif ($token->id === T_LNUMBER) {
                $value->literal = $token->text;
            } elseif ($token->is([T_STRING, T_NAME_FULLY_QUALIFIED, T_EVAL])) {
                $name = strtolower(ltrim($token->text, '\\'));
                $previous = $this->tokens[$i - 1] ?? null;
                if ($previous?->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW, T_FUNCTION])) {
                    $class = strtolower(ltrim($this->tokens[$i - 2]->text ?? '', '\\'));
                    $name = $previous->id === T_DOUBLE_COLON && in_array($class, $this->requestFacades, true)
                        && in_array($name, ['input', 'query', 'post', 'get', 'cookie', 'file', 'all', 'getcontent'], true) ? '__laravel_input__' : '__unknown__';
                }
            } elseif ($token->is([T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE])) {
                $value = $this->expression($i + 1, $end, $variables, $depth + 1);
                if ($value->sources !== []) {
                    $this->add('PHP-INPUT-INCLUDE', $token->line, ['http_input'], $value, 'include');
                } elseif ($value->literal !== null && preg_match('~^(https?|ftp|data|php)://~i', $value->literal)) {
                    $this->add('PHP-REMOTE-INCLUDE', $token->line, ['remote_include'], $value, 'include');
                }

                return $value;
            } elseif ($token->text === '(') {
                $value = $this->expression($i + 1, $this->pairs[$i], $variables, $depth + 1);
                $i = $this->pairs[$i];
            } elseif ($token->text === '$') {
                $this->add('PHP-DYNAMIC-CALL', $token->line, ['variable_variables'], $value, null, 'low');
            } elseif ($token->text === '.') {
                continue;
            }
            if (($name !== null || $dynamic) && ($this->tokens[$i + 1]->text ?? '') === '(') {
                $close = $this->pairs[$i + 1];
                $arguments = [];
                $argumentStart = $i + 2;
                for ($p = $argumentStart; $p < $close; $p++) {
                    if (isset($this->pairs[$p])) {
                        $p = $this->pairs[$p];
                    } elseif ($this->tokens[$p]->text === ',') {
                        $arguments[] = $this->expression($argumentStart, $p, $variables, $depth + 1);
                        $argumentStart = $p + 1;
                    }
                }
                if ($argumentStart < $close) {
                    $arguments[] = $this->expression($argumentStart, $close, $variables, $depth + 1);
                }
                $value = $this->call($name, $arguments, $value, $dynamic, $token->line);
                $i = $close;
            }
            if ($value->request && ($this->tokens[$i + 1]->id ?? null) === T_OBJECT_OPERATOR
                && in_array(strtolower($this->tokens[$i + 2]->text ?? ''), ['input', 'query', 'post', 'get', 'cookie', 'file', 'all', 'getcontent'], true)
                && ($this->tokens[$i + 3]->text ?? '') === '(') {
                $value = new FlowValue(['laravel_request']);
                $i = $this->pairs[$i + 3];
            }
            $literalOnly = $literalOnly && $value->literal !== null;
            $literal .= $value->literal ?? '';
            $result = $result->merge($value);
        }
        $result->literal = $literalOnly && strlen($literal) <= 256 ? $literal : null;

        return $result;
    }

    /** @param list<FlowValue> $arguments */
    private function call(?string $name, array $arguments, FlowValue $callable, bool $dynamic, int $line): FlowValue
    {
        $name = $name !== null ? strtolower(ltrim($name, '\\')) : null;
        $value = $arguments[0] ?? new FlowValue;
        if ($name === '__laravel_input__') {
            return new FlowValue(['laravel_request']);
        }
        if ($dynamic && ($callable->sources !== [] || $name === null)) {
            $this->add($callable->sources !== [] ? 'PHP-INPUT-EXEC' : 'PHP-DYNAMIC-CALL', $line,
                $callable->sources !== [] ? ['http_input', 'execution', 'dynamic_call'] : ['dynamic_call'], $callable, 'dynamic', 'medium');
        }
        if ($name === 'request' && ! $dynamic) {
            return $arguments === []
                ? new FlowValue(request: true) : new FlowValue(['laravel_request']);
        }
        if (in_array($name, RiskScorer::ENCODERS, true)) {
            $result = clone $value;
            $result->literal = null;
            $result->encoders = array_slice([...$value->encoders, $name], 0, 8);
            if (count($result->encoders) >= 2) {
                $this->add('PHP-OBFUSCATION', $line, ['nested_encoding'], $result, null, 'medium');
            }

            return $result;
        }
        if ($name === 'chr' && $value->literal !== null && ctype_digit($value->literal) && (int) $value->literal <= 127) {
            return new FlowValue(literal: chr((int) $value->literal));
        }
        if ((! $dynamic && $name === 'eval') || in_array($name, ['system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen'], true)) {
            $id = $value->sources !== [] ? 'PHP-INPUT-EXEC' : ($name === 'eval' ? ($value->encoders !== [] ? 'PHP-ENCODED-EVAL' : 'PHP-EVAL') : 'PHP-PROCESS');
            $signals = ['execution'];
            if ($value->sources !== []) {
                $signals[] = 'http_input';
            }
            if ($value->encoders !== []) {
                $signals[] = 'encoded_payload';
            }
            if ($dynamic) {
                $signals[] = 'dynamic_call';
            }
            $this->add($id, $line, $signals, $value, $name);
        }
        if ($name === 'unserialize' && $value->sources !== []) {
            $this->add('PHP-INPUT-UNSERIALIZE', $line, ['http_input'], $value, 'unserialize');
        }
        $result = new FlowValue;
        foreach ($arguments as $argument) {
            $result = $result->merge($argument);
        }
        $result->uncertain = true;

        return $result;
    }

    /** @param list<string> $signals */
    private function add(string $id, int $line, array $signals, FlowValue $value, ?string $sink, ?string $confidence = null): void
    {
        if ($value->uncertain) {
            $signals[] = 'uncertain_flow';
        }
        $this->findings[$id.':'.$line] = ['rule_id' => $id, 'line' => $line, 'signals' => $signals,
            'input_sources' => $value->sources, 'encoding_layers' => array_values(array_unique($value->encoders)),
            'sink' => $sink, 'confidence' => $confidence ?? ($value->uncertain ? 'medium' : 'high')];
        if (count($this->findings) > 1000) {
            throw new RuntimeException('PHP analysis finding limit exceeded.');
        }
    }

    private function budget(int $depth): void
    {
        if ($depth > 64 || ++$this->work > 500000) {
            throw new RuntimeException('PHP analysis complexity limit exceeded.');
        }
    }
}

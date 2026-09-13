<?php

namespace BasicXII\CloudSecurity\Scanner;

use RuntimeException;

class Quarantine
{
    public function move(string $root, LocalState $state, string $commandId, string $fileId, string $sha256): void
    {
        if (! preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/Di', $commandId)
            || ! preg_match('/^[a-f0-9]{64}$/D', $fileId) || ! preg_match('/^[a-f0-9]{64}$/D', $sha256)) {
            throw new RuntimeException('Invalid quarantine identifiers.');
        }
        $path = ($state->read('paths.json') ?? [])[$fileId] ?? null;
        $root = realpath($root);
        $directory = realpath($state->directory());
        if (! is_string($path) || $root === false || $directory === false || str_contains($path, '..')
            || ! preg_match('~^[a-zA-Z0-9_./ -]+$~D', $path) || str_starts_with($path, '/')
            || ! hash_equals($state->identifier($path), $fileId)
            || str_starts_with($directory.DIRECTORY_SEPARATOR, $root.DIRECTORY_SEPARATOR.'public'.DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Quarantine path is unsafe.');
        }
        $source = $root;
        foreach (explode('/', $path) as $segment) {
            $source .= DIRECTORY_SEPARATOR.$segment;
            if (is_link($source)) {
                throw new RuntimeException('Symbolic links cannot be quarantined.');
            }
        }
        $resolved = realpath($source);
        if ($resolved === false || ! str_starts_with($resolved, $root.DIRECTORY_SEPARATOR)
            || ! is_file($source) || ! hash_equals($sha256, (string) @hash_file('sha256', $source))) {
            throw new RuntimeException('The reviewed file changed or is unavailable.');
        }
        $target = $directory.'/quarantine-'.$commandId.'.bin';
        if (file_exists($target) || is_link($target)) {
            throw new RuntimeException('Quarantine destination already exists.');
        }
        $mode = fileperms($source) & 0777;
        $state->save('quarantine-'.$commandId.'.json', ['original_path' => $path, 'sha256' => $sha256, 'mode' => $mode, 'status' => 'prepared']);
        if (! @rename($source, $target)) {
            throw new RuntimeException('Unable to quarantine the file.');
        }
        @chmod($target, 0600);
        if (! hash_equals($sha256, (string) @hash_file('sha256', $target))) {
            throw new RuntimeException('Quarantined file changed during the operation; local review required.');
        }
        $state->save('quarantine-'.$commandId.'.json', ['original_path' => $path, 'sha256' => $sha256, 'mode' => $mode, 'status' => 'quarantined']);
    }

    public function restore(string $root, LocalState $state, string $commandId): void
    {
        if (! preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/Di', $commandId)) {
            throw new RuntimeException('Invalid quarantine identifier.');
        }
        $metadata = $state->read('quarantine-'.$commandId.'.json');
        $path = $metadata['original_path'] ?? null;
        $root = realpath($root);
        if ($root === false || ! is_string($path) || str_contains($path, '..') || str_starts_with($path, '/')
            || ! preg_match('~^[a-zA-Z0-9_./ -]+$~D', $path) || ! in_array($metadata['status'] ?? null, ['prepared', 'quarantined'], true)) {
            throw new RuntimeException('Invalid recovery metadata.');
        }
        $target = $root;
        foreach (explode('/', $path) as $segment) {
            $target .= DIRECTORY_SEPARATOR.$segment;
            if (is_link($target)) {
                throw new RuntimeException('Recovery through symbolic links is prohibited.');
            }
        }
        $source = $state->directory().'/quarantine-'.$commandId.'.bin';
        if (file_exists($target) || ! is_dir(dirname($target)) || is_link($source)
            || ! is_string($metadata['sha256'] ?? null) || ! hash_equals($metadata['sha256'], (string) @hash_file('sha256', $source))) {
            throw new RuntimeException('Recovery would overwrite a file or the quarantined hash changed.');
        }
        if (! @rename($source, $target)) {
            throw new RuntimeException('Unable to restore quarantine.');
        }
        @chmod($target, ($metadata['mode'] ?? 0600) & 0666);
        $state->save('quarantine-'.$commandId.'.json', [...$metadata, 'status' => 'restored']);
    }
}

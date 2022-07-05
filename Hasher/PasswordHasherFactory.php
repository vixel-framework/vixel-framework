<?php
/**
 * GNU Lesser General Public License v2.1.
 *
 * Copyright (c) 2022 Nicholas English
 *
 * Primarily used for software libraries, the GNU LGPL requires that derived works be licensed under the same
 * license, but works that only link to it do not fall under this restriction. There are two commonly used
 * versions of the GNU LGPL.
 *
 * @author <https://github.com/omatamix> Nicholas English
 */

namespace Vixel\Hasher;

use RuntimeException;
use UnexpectedValueException;

class PasswordHasherFactory implements PasswordHasherFactoryInterface, PasswordHasherInterface
{
    /** @var \Vixel\Hasher\PasswordHasherInterface|null The built password hasher. */
    private PasswordHasherInterface|null $passwordHasher = null;

    /** @var array A list of string aliases toward the password hasher constants. */
    protected static array $aliases = [
        'moderate'    => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        'interactive' => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        'sensitive'   => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
        'default'     => \PASSWORD_DEFAULT,
        'bcrypt'      => \PASSWORD_BCRYPT,
        'argon2i'     => \PASSWORD_ARGON2I,
        'argon2id'    => \PASSWORD_ARGON2ID,
    ];

    /** @var array A list of supported password hashers. */
    protected static array $supportedPasswordHashers = [
        'standard',
        'sodium',
    ];

    /** @var array A list of supported sodium options. */
    protected static array $supportedSodiumOptions = [
        'moderate',
        'interactive',
        'sensitive',
    ];

    /** @var array A list of supported password algos. */
    protected static array $supportedAlgos = [
        'default',
        'bcrypt',
        'argon2i',
        'argon2id',
    ];

    /**
     * Construct a new password hasher factory.
     *
     * @param string $passwordHasher The password hasher to build.
     * @param array  $options        A list of options for the password hasher.
     *
     * @return void Returns nothing.
     */
    public function __construct(string $passwordHasher = '', array $options)
    {
        if ($passwordHasher !== '') {
            $this->buildHasher($passwordHasher, $options);
        }
    }

    /**
     * Build a new password hasher.
     *
     * @param string $desiredHasher The password hasher to use.
     * @param array  $options       A list of options for the password hasher.
     *
     * @return \Vixel\Hasher\PasswordHasherFactoryInterface Return the password hasher factory.
     */
    public function buildHasher(string $desiredHasher, array $options = []): PasswordHasherFactoryInterface
    {
        if (!\in_array($desiredHasher, static::$supportedPasswordHashers)) {
            throw new UnexpectedValueException('This password hasher is not supported.');
        }
        if (!isset($options['algo'])) {
            $options['algo'] = $this->aliases['default'];
        } elseif (!\in_array($options['algo'], static::$supportedAlgos)) {
            throw new UnexpectedValueException('The password algorithm supplied is not supported.');
        } else {
            $options['algo'] = $this->aliases[$options['algo']];
        }
        if (!isset($options['opslimit'])) {
            $options['opslimit'] = $this->aliases['moderate'];
        } elseif (!\in_array($options['opslimit'], static::$supportedSodiumOptions)) {
            throw new UnexpectedValueException('The ops limit supplied is not supported.');
        } else {
            $options['opslimit'] = $this->aliases[$options['opslimit']];
        }
        if (!isset($options['memlimit'])) {
            $options['memlimit'] = $this->aliases['moderate'];
        } elseif (!\in_array($options['memlimit'], static::$supportedSodiumOptions)) {
            throw new UnexpectedValueException('The mem limit supplied is not supported.');
        } else {
            $options['memlimit'] = $this->aliases[$options['memlimit']];
        }
        if ($desiredHasher === 'standard') {
            $this->passwordHasher = new PasswordHasher($options['algo'], $options);
        } else {
            $this->passwordHasher = new SodiumPasswordHasher($options);
        }

        return $this;
    }

    /**
     * Compute a new hash.
     *
     * @param string $password The password to hash.
     *
     * @throws \InvalidArgumentException If the password suppied is too long.
     * @throws \RuntimeException         If a password hasher was not built.
     *
     * @return string Returns the hashed password.
     */
    public function compute(string $password): string
    {
        if (\is_null($this->passwordHasher)) {
            throw new RuntimeException('A password hasher was not built.');
        }

        return $this->passwordHasher->compute($password);
    }

    /**
     * Verify the password matches the hash provided.
     *
     * @param string $password The password check.
     * @param string $hash     The hash to check against.
     *
     * @throws \RuntimeException If a password hasher was not built.
     *
     * @return bool Returns true if the password matches the given hash else return false.
     */
    public function verify(string $password, string $hash): bool
    {
        if (\is_null($this->passwordHasher)) {
            throw new RuntimeException('A password hasher was not built.');
        }

        return $this->passwordHasher->verify($password, $hash);
    }

    /**
     * Determine if the hash needs a rehash.
     *
     * @param string $hash The hash to check.
     *
     * @throws \RuntimeException If a password hasher was not built.
     *
     * @return bool Returns true if the hash needs a rehash and false if not.
     */
    public function needsRehash(string $hash): bool
    {
        if (\is_null($this->passwordHasher)) {
            throw new RuntimeException('A password hasher was not built.');
        }

        return $this->passwordHasher->needsRehash($hash);
    }

    /**
     * Clear the password hasher from memory.
     *
     * @return void Returns nothing.
     */
    public function clearHasher(): void
    {
        $this->passwordHasher = null;
    }
}

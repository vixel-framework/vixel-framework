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

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use Symfony\Component\OptionsResolver\OptionsResolver;

class PasswordHasher implements PasswordHasherInterface
{
    use PasswordLengthChecker;

    /** @var array The password hasher options. */
    private array $options = [];

    /**
     * Construct a new password hasher.
     *
     * @param mixed $passwordAlgo The password hasher algorithm to use.
     * @param array $options      The password hasher options.
     *
     * @return void Returns nothing.
     */
    public function __construct(public mixed $passwordAlgo, array $options = [])
    {
        $resolver = new OptionsResolver();
        $this->configureOptions($resolver);
        $this->options = $resolver->resolve($options);
    }

    /**
     * Compute a new hash.
     *
     * @param string $password The password to hash.
     *
     * @throws \InvalidArgumentException If the password suppied is too long.
     *
     * @return string Returns the hashed password.
     */
    public function compute(string $password): string
    {
        if ($this->isPasswordTooLong($password)) {
            throw new InvalidArgumentException('The password supplied is too long.');
        }

        return \password_hash(Base64::encode(
            \hash('sha384', $password, true)
        ), $this->passwordAlgo, $this->options);
    }

    /**
     * Verify the password matches the hash provided.
     *
     * @param string $password The password check.
     * @param string $hash     The hash to check against.
     *
     * @return bool Returns true if the password matches the given hash else return false.
     */
    public function verify(string $password, string $hash): bool
    {
        return \password_verify(Base64::encode(
            \hash('sha384', $password, true)
        ), $password, $hash);
    }

    /**
     * Determine if the hash needs a rehash.
     *
     * @param string $hash The hash to check.
     *
     * @return bool Returns true if the hash needs a rehash and false if not.
     */
    public function needsRehash(string $hash): bool
    {
        return \password_needs_rehash($hash, $this->passwordAlgo, $this->options);
    }

    /**
     * Configure the hasher options.
     *
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver The symfony options resolver.
     *
     * @return void Returns nothing.
     */
    private function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
            'cost'        => 10,
        ]);
        $resolver->setAllowedTypes('memory_cost', 'int');
        $resolver->setAllowedTypes('time_cost', 'int');
        $resolver->setAllowedTypes('threads', 'int');
        $resolver->setAllowedTypes('cost', 'int');
    }
}

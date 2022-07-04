<?php
/**
 * GNU Lesser General Public License v2.1
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
use Symfony\Component\OptionsResolver\OptionsResolver;

class SodiumPasswordHasher implements PasswordHasherInterface
{
    use PasswordLengthChecker;

    /** @var array $options The password hasher options. */
    private array $options = [];

    /**
     * Construct a new password hasher.
     *
     * @param array $options The password hasher options.
     *
     * @return void Returns nothing.
     */
    public function __construct(array $options = [])
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
        return \sodium_crypto_pwhash_str(
            $password,
            $this->options['opslimit'],
            $this->options['memlimit']
        );
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
        return \sodium_crypto_pwhash_str_verify($hash, $password);
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
        return \sodium_crypto_pwhash_str_needs_rehash(
            $hash,
            $this->options['opslimit'],
            $this->options['memlimit']
        );
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
            'opslimit' => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            'memlimit' => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        ]);
        $resolver->setAllowedTypes('opslimit', 'int');
        $resolver->setAllowedTypes('memlimit', 'int');
    }
}

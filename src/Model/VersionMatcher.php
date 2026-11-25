<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

use Composer\Semver\Comparator;
use Composer\Semver\Semver;
use Composer\Semver\VersionParser;

/**
 * Composer-aware version helpers (understands Magento patch versions like 2.4.8-p3).
 */
class VersionMatcher
{
    /**
     * @var VersionParser
     */
    private VersionParser $parser;

    /**
     * @param VersionParser|null $parser
     */
    public function __construct(?VersionParser $parser = null)
    {
        $this->parser = $parser ?? new VersionParser();
    }

    /**
     * Whether the version satisfies a Composer constraint such as ">=2.4.7-beta1,<2.4.7-p8|=2.4.6".
     *
     * @param string $version
     * @param string $constraint
     * @return bool
     */
    public function satisfies(string $version, string $constraint): bool
    {
        if (!$this->isValid($version) || trim($constraint) === '') {
            return false;
        }
        try {
            return Semver::satisfies($version, $constraint);
        } catch (\UnexpectedValueException $e) {
            return false;
        }
    }

    /**
     * Whether $a is a lower version than $b.
     *
     * @param string $a
     * @param string $b
     * @return bool
     */
    public function lessThan(string $a, string $b): bool
    {
        if (!$this->isValid($a) || !$this->isValid($b)) {
            return false;
        }
        return Comparator::lessThan($this->parser->normalize($a), $this->parser->normalize($b));
    }

    /**
     * Whether the string is a version Composer can compare (not "dev-main", not a commit hash).
     *
     * @param string $version
     * @return bool
     */
    public function isValid(string $version): bool
    {
        if ($version === '' || str_starts_with($version, 'dev-') || str_ends_with($version, '-dev')) {
            return false;
        }
        try {
            $this->parser->normalize($version);
            return true;
        } catch (\UnexpectedValueException $e) {
            return false;
        }
    }

    /**
     * Release line of a Magento version, e.g. "2.4.8" for "2.4.8-p3".
     *
     * @param string $version
     * @return string
     */
    public function releaseLine(string $version): string
    {
        return preg_match('/^(\d+\.\d+\.\d+)/', $version, $m) ? $m[1] : '';
    }

    /**
     * Highest stable Magento patch release per release line from a list of versions.
     *
     * @param string[] $versions
     * @return array<string,string> e.g. ["2.4.8" => "2.4.8-p5"]
     */
    public function latestPatchPerLine(array $versions): array
    {
        $latest = [];
        foreach ($versions as $version) {
            if (!preg_match('/^(\d+\.\d+\.\d+)(?:-p\d+)?$/', $version, $m)) {
                continue; // skip alpha, beta, RC
            }
            $line = $m[1];
            if (!isset($latest[$line]) || $this->lessThan($latest[$line], $version)) {
                $latest[$line] = $version;
            }
        }
        uksort($latest, static fn (string $a, string $b): int => version_compare($a, $b));
        return $latest;
    }
}

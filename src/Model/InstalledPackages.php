<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

use Composer\InstalledVersions;

/**
 * Installed Composer packages and their versions (from Composer's runtime API).
 */
class InstalledPackages
{
    /**
     * @var VersionMatcher
     */
    private VersionMatcher $versions;

    /**
     * @param VersionMatcher $versions
     */
    public function __construct(VersionMatcher $versions)
    {
        $this->versions = $versions;
    }

    /**
     * Package name => pretty version, for packages with a comparable version.
     *
     * @return array<string,string>
     */
    public function getVersions(): array
    {
        if (!class_exists(InstalledVersions::class)) {
            return [];
        }
        $result = [];
        foreach (InstalledVersions::getInstalledPackages() as $name) {
            if (!preg_match('#^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$#', $name)) {
                continue; // virtual/provided names such as "php" or "ext-*"
            }
            try {
                $version = (string) InstalledVersions::getPrettyVersion($name);
            } catch (\OutOfBoundsException $e) {
                continue;
            }
            if ($this->versions->isValid($version)) {
                $result[$name] = ltrim($version, 'v');
            }
        }
        ksort($result);
        return $result;
    }
}

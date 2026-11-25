<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Remote;

use MeetMage\SecurityHealthCheck\Model\Config;

/**
 * Public data the checks need. Only package names are sent out; installed versions never leave the server.
 */
class DataSources
{
    private const ADVISORY_URL = 'https://packagist.org/api/security-advisories/';
    private const EOL_URL = 'https://endoflife.date/api/%s.json';
    private const BATCH = 100;

    /**
     * @var JsonClient
     */
    private JsonClient $client;

    /**
     * @var Config
     */
    private Config $config;

    /**
     * @param JsonClient $client
     * @param Config $config
     */
    public function __construct(JsonClient $client, Config $config)
    {
        $this->client = $client;
        $this->config = $config;
    }

    /**
     * Whether external lookups are allowed.
     *
     * @return bool
     */
    public function isAvailable(): bool
    {
        return $this->config->isExternalLookupAllowed();
    }

    /**
     * Known security advisories for the given Composer packages, keyed by package name.
     *
     * Returns null when the lookup failed or is switched off.
     *
     * @param string[] $packages
     * @return array<string,array<int,array<string,mixed>>>|null
     */
    public function getAdvisories(array $packages): ?array
    {
        if (!$this->isAvailable()) {
            return null;
        }
        $packages = array_values(array_unique($packages));
        sort($packages);
        $result = [];
        foreach (array_chunk($packages, self::BATCH) as $chunk) {
            $data = $this->client->post(self::ADVISORY_URL, ['packages' => $chunk]);
            if ($data === null || !isset($data['advisories']) || !is_array($data['advisories'])) {
                return null;
            }
            foreach ($data['advisories'] as $name => $list) {
                if (is_array($list) && $list) {
                    $result[(string) $name] = array_values(array_filter($list, 'is_array'));
                }
            }
        }
        return $result;
    }

    /**
     * Release cycles from endoflife.date for a product ("magento" or "php").
     *
     * @param string $product
     * @return array<int,array<string,mixed>>|null
     */
    public function getLifecycle(string $product): ?array
    {
        if (!$this->isAvailable() || !preg_match('/^[a-z0-9-]+$/', $product)) {
            return null;
        }
        $data = $this->client->get(sprintf(self::EOL_URL, $product), 86400);
        return $data === null ? null : array_values(array_filter($data, 'is_array'));
    }

    /**
     * All released Magento Open Source versions from the Composer release feed.
     *
     * @return string[]|null
     */
    public function getMagentoReleases(): ?array
    {
        if (!$this->isAvailable()) {
            return null;
        }
        $data = $this->client->get($this->config->getReleaseFeedUrl());
        $list = $data['packages']['magento/product-community-edition'] ?? null;
        if (!is_array($list)) {
            return null;
        }
        $versions = [];
        foreach ($list as $item) {
            if (is_array($item) && isset($item['version'])) {
                $versions[] = (string) $item['version'];
            }
        }
        return $versions ?: null;
    }
}

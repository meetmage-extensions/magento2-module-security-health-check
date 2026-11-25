<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Remote;

use Magento\Framework\App\CacheInterface;
use Magento\Framework\HTTP\Client\CurlFactory;
use Magento\Framework\Serialize\Serializer\Json;
use Psr\Log\LoggerInterface;

/**
 * Small cached JSON client for the public data sources (Packagist, endoflife.date, release feed).
 * Failures are logged and return null, so a network problem never breaks the admin or cron.
 */
class JsonClient
{
    private const CACHE_PREFIX = 'meetmage_shc_';
    private const CACHE_TAG = 'MEETMAGE_SHC';
    private const TIMEOUT = 15;

    /**
     * @var CurlFactory
     */
    private CurlFactory $curlFactory;

    /**
     * @var CacheInterface
     */
    private CacheInterface $cache;

    /**
     * @var Json
     */
    private Json $json;

    /**
     * @var LoggerInterface
     */
    private LoggerInterface $logger;

    /**
     * @param CurlFactory $curlFactory
     * @param CacheInterface $cache
     * @param Json $json
     * @param LoggerInterface $logger
     */
    public function __construct(CurlFactory $curlFactory, CacheInterface $cache, Json $json, LoggerInterface $logger)
    {
        $this->curlFactory = $curlFactory;
        $this->cache = $cache;
        $this->json = $json;
        $this->logger = $logger;
    }

    /**
     * GET a JSON document (cached).
     *
     * @param string $url
     * @param int $ttl Cache lifetime in seconds
     * @return array<mixed>|null
     */
    public function get(string $url, int $ttl = 43200): ?array
    {
        return $this->request('GET', $url, [], $ttl);
    }

    /**
     * POST form data and read a JSON response (cached by URL + body).
     *
     * @param string $url
     * @param array<string,mixed> $form
     * @param int $ttl Cache lifetime in seconds
     * @return array<mixed>|null
     */
    public function post(string $url, array $form, int $ttl = 43200): ?array
    {
        return $this->request('POST', $url, $form, $ttl);
    }

    /**
     * Remove cached responses so the next check fetches fresh data.
     *
     * @return void
     */
    public function clean(): void
    {
        $this->cache->clean([self::CACHE_TAG]);
    }

    /**
     * Perform the request.
     *
     * @param string $method
     * @param string $url
     * @param array<string,mixed> $form
     * @param int $ttl
     * @return array<mixed>|null
     */
    private function request(string $method, string $url, array $form, int $ttl): ?array
    {
        $body = $method === 'POST' ? http_build_query($form) : '';
        $key = self::CACHE_PREFIX . hash('sha256', $method . ' ' . $url . ' ' . $body);
        $cached = $this->cache->load($key);
        if (is_string($cached) && $cached !== '') {
            $data = $this->decode($cached);
            if ($data !== null) {
                return $data;
            }
        }

        try {
            $curl = $this->curlFactory->create();
            $curl->setTimeout(self::TIMEOUT);
            $curl->setOptions([CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3]);
            $curl->addHeader('Accept', 'application/json');
            $curl->addHeader('User-Agent', 'MeetMage-SecurityHealthCheck/1.0 (+https://meetshekhat.com)');
            if ($method === 'POST') {
                // Form-encoded body built with http_build_query keeps "packages[]" style keys intact.
                $curl->addHeader('Content-Type', 'application/x-www-form-urlencoded');
                $curl->post($url, $body);
            } else {
                $curl->get($url);
            }
            $status = $curl->getStatus();
            $response = $curl->getBody();
        } catch (\Exception $e) {
            $this->logger->warning('[SecurityHealthCheck] Request failed: ' . $url . ' ' . $e->getMessage());
            return null;
        }

        if ($status < 200 || $status >= 300) {
            $this->logger->warning(sprintf('[SecurityHealthCheck] %s returned HTTP %d', $url, $status));
            return null;
        }
        $data = $this->decode($response);
        if ($data === null) {
            $this->logger->warning('[SecurityHealthCheck] Invalid JSON from ' . $url);
            return null;
        }
        $this->cache->save($response, $key, [self::CACHE_TAG], $ttl);
        return $data;
    }

    /**
     * Decode JSON safely.
     *
     * @param string $raw
     * @return array<mixed>|null
     */
    private function decode(string $raw): ?array
    {
        try {
            $data = $this->json->unserialize($raw);
        } catch (\InvalidArgumentException $e) {
            return null;
        }
        return is_array($data) ? $data : null;
    }
}

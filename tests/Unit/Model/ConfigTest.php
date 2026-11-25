<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Test\Unit\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use MeetMage\SecurityHealthCheck\Model\Config;
use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{
    private function config(array $values): Config
    {
        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('getValue')->willReturnCallback(static fn (string $path) => $values[$path] ?? null);
        $scopeConfig->method('isSetFlag')->willReturnCallback(static fn (string $path) => !empty($values[$path]));
        return new Config($scopeConfig);
    }

    public function testRecipientsKeepOnlyValidEmails(): void
    {
        $config = $this->config([Config::XML_PATH_EMAIL_RECIPIENTS => 'a@example.com, nope ; b@example.org']);
        $this->assertSame(['a@example.com', 'b@example.org'], $config->getEmailRecipients());
    }

    public function testIgnoredChecksSplitOnLinesAndCommas(): void
    {
        $config = $this->config([Config::XML_PATH_IGNORED => "admin.captcha\nconfig.cron, packages.advisories.foo/*"]);
        $this->assertSame(['admin.captcha', 'config.cron', 'packages.advisories.foo/*'], $config->getIgnoredChecks());
    }

    public function testReleaseFeedMustBeHttps(): void
    {
        $this->assertSame(
            Config::DEFAULT_RELEASE_FEED,
            $this->config([Config::XML_PATH_MIRROR => 'http://evil.example/feed.json'])->getReleaseFeedUrl()
        );
        $this->assertSame(
            'https://repo.example/p2/x.json',
            $this->config([Config::XML_PATH_MIRROR => 'https://repo.example/p2/x.json'])->getReleaseFeedUrl()
        );
    }

    public function testUnknownFrequencyFallsBackToWeekly(): void
    {
        $this->assertSame(
            Config::FREQUENCY_WEEKLY,
            $this->config([Config::XML_PATH_EMAIL_FREQUENCY => 'hourly'])->getEmailFrequency()
        );
        $this->assertSame(
            Config::FREQUENCY_DAILY,
            $this->config([Config::XML_PATH_EMAIL_FREQUENCY => 'daily'])->getEmailFrequency()
        );
    }
}

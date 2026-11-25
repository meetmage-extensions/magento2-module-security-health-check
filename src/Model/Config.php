<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;

/**
 * Typed access to the module's admin configuration (Stores > Configuration > MeetMage > Security Health Check).
 * All settings are global: the check looks at the whole installation.
 */
class Config
{
    public const XML_PATH_ENABLED = 'meetmage_securityhealthcheck/general/enabled';
    public const XML_PATH_EXTERNAL = 'meetmage_securityhealthcheck/general/external_lookups';
    public const XML_PATH_MIRROR = 'meetmage_securityhealthcheck/general/release_feed_url';
    public const XML_PATH_IGNORED = 'meetmage_securityhealthcheck/general/ignored_checks';
    public const XML_PATH_EMAIL_ENABLED = 'meetmage_securityhealthcheck/email/enabled';
    public const XML_PATH_EMAIL_FREQUENCY = 'meetmage_securityhealthcheck/email/frequency';
    public const XML_PATH_EMAIL_RECIPIENTS = 'meetmage_securityhealthcheck/email/recipients';
    public const XML_PATH_EMAIL_IDENTITY = 'meetmage_securityhealthcheck/email/identity';
    public const XML_PATH_EMAIL_TEMPLATE = 'meetmage_securityhealthcheck/email/template';

    public const FREQUENCY_NEW = 'new';
    public const FREQUENCY_WEEKLY = 'weekly';
    public const FREQUENCY_DAILY = 'daily';

    public const DEFAULT_RELEASE_FEED = 'https://mirror.mage-os.org/p2/magento/product-community-edition.json';

    /**
     * @var ScopeConfigInterface
     */
    private ScopeConfigInterface $scopeConfig;

    /**
     * @param ScopeConfigInterface $scopeConfig
     */
    public function __construct(ScopeConfigInterface $scopeConfig)
    {
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * Whether the scheduled check runs.
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_PATH_ENABLED);
    }

    /**
     * Whether the check may call Packagist, endoflife.date and the release feed.
     *
     * @return bool
     */
    public function isExternalLookupAllowed(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_PATH_EXTERNAL);
    }

    /**
     * Composer metadata URL listing Magento Open Source releases.
     *
     * @return string
     */
    public function getReleaseFeedUrl(): string
    {
        $url = trim((string) $this->scopeConfig->getValue(self::XML_PATH_MIRROR));
        return str_starts_with($url, 'https://') ? $url : self::DEFAULT_RELEASE_FEED;
    }

    /**
     * Finding codes the merchant chose to ignore.
     *
     * @return string[]
     */
    public function getIgnoredChecks(): array
    {
        $value = (string) $this->scopeConfig->getValue(self::XML_PATH_IGNORED);
        return array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', $value) ?: [])));
    }

    /**
     * Whether report emails are on.
     *
     * @return bool
     */
    public function isEmailEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_PATH_EMAIL_ENABLED);
    }

    /**
     * When to send the report email.
     *
     * @return string
     */
    public function getEmailFrequency(): string
    {
        $value = (string) $this->scopeConfig->getValue(self::XML_PATH_EMAIL_FREQUENCY);
        return in_array($value, [self::FREQUENCY_NEW, self::FREQUENCY_WEEKLY, self::FREQUENCY_DAILY], true)
            ? $value
            : self::FREQUENCY_WEEKLY;
    }

    /**
     * Valid recipient email addresses.
     *
     * @return string[]
     */
    public function getEmailRecipients(): array
    {
        $value = (string) $this->scopeConfig->getValue(self::XML_PATH_EMAIL_RECIPIENTS);
        $emails = array_map('trim', preg_split('/[\s,;]+/', $value) ?: []);
        return array_values(array_filter(
            $emails,
            static fn (string $email): bool => (bool) filter_var($email, FILTER_VALIDATE_EMAIL)
        ));
    }

    /**
     * Sender identity code (general, sales, ...).
     *
     * @return string
     */
    public function getEmailIdentity(): string
    {
        return (string) ($this->scopeConfig->getValue(self::XML_PATH_EMAIL_IDENTITY) ?: 'general');
    }

    /**
     * Email template identifier.
     *
     * @return string
     */
    public function getEmailTemplate(): string
    {
        return (string) ($this->scopeConfig->getValue(self::XML_PATH_EMAIL_TEMPLATE)
            ?: 'meetmage_securityhealthcheck_email_template');
    }
}

<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Check;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\App\State;
use Magento\Framework\Module\Manager as ModuleManager;
use Magento\Framework\Stdlib\DateTime\DateTime;
use Magento\Store\Model\ScopeInterface;
use Magento\Store\Model\StoreManagerInterface;
use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\Severity;

/**
 * Configuration that protects the admin and the store (PCI DSS references where they apply).
 */
class Hardening implements CheckInterface
{
    private const COMMON_ADMIN_NAMES = ['admin', 'administrator', 'root', 'test', 'demo', 'magento'];

    private const TFA_DOCS = 'https://experienceleague.adobe.com/en/docs/commerce-admin/systems/security/2fa/'
        . 'security-two-factor-authentication';

    /**
     * @var ScopeConfigInterface
     */
    private ScopeConfigInterface $scopeConfig;

    /**
     * @var DeploymentConfig
     */
    private DeploymentConfig $deploymentConfig;

    /**
     * @var State
     */
    private State $appState;

    /**
     * @var ModuleManager
     */
    private ModuleManager $moduleManager;

    /**
     * @var StoreManagerInterface
     */
    private StoreManagerInterface $storeManager;

    /**
     * @var ResourceConnection
     */
    private ResourceConnection $resource;

    /**
     * @var DateTime
     */
    private DateTime $dateTime;

    /**
     * @param ScopeConfigInterface $scopeConfig
     * @param DeploymentConfig $deploymentConfig
     * @param State $appState
     * @param ModuleManager $moduleManager
     * @param StoreManagerInterface $storeManager
     * @param ResourceConnection $resource
     * @param DateTime $dateTime
     */
    public function __construct(
        ScopeConfigInterface $scopeConfig,
        DeploymentConfig $deploymentConfig,
        State $appState,
        ModuleManager $moduleManager,
        StoreManagerInterface $storeManager,
        ResourceConnection $resource,
        DateTime $dateTime
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->deploymentConfig = $deploymentConfig;
        $this->appState = $appState;
        $this->moduleManager = $moduleManager;
        $this->storeManager = $storeManager;
        $this->resource = $resource;
        $this->dateTime = $dateTime;
    }

    /**
     * @inheritDoc
     */
    public function run(): array
    {
        return [
            $this->productionMode(),
            $this->adminPath(),
            $this->twoFactorAuth(),
            $this->https(),
            $this->adminUsernames(),
            $this->accountSharing(),
            $this->lockout(),
            $this->sessionLifetime(),
            $this->adminCaptcha(),
            $this->secretKeyUrls(),
            $this->contentSecurityPolicy(),
            $this->templateHints(),
            $this->cron(),
        ];
    }

    /**
     * Production mode hides errors and stack traces from visitors.
     *
     * @return Finding
     */
    private function productionMode(): Finding
    {
        try {
            $mode = $this->appState->getMode();
        } catch (\Exception $e) {
            $mode = (string) $this->deploymentConfig->get('MAGE_MODE');
        }
        if ($mode === State::MODE_PRODUCTION) {
            return $this->passed('config.production_mode', Report::CATEGORY_CONFIG, __('Production mode is on'));
        }
        return new Finding(
            'config.production_mode',
            Report::CATEGORY_CONFIG,
            $mode === State::MODE_DEVELOPER ? Severity::HIGH : Severity::MEDIUM,
            (string) __('The store runs in %1 mode', $mode ?: State::MODE_DEFAULT),
            (string) __('Outside production mode Magento can show error details and file paths to visitors, '
                . 'and it is slower.'),
            (string) __('Run: bin/magento deploy:mode:set production (on a live store, during a quiet period).')
        );
    }

    /**
     * A custom admin path stops automated login attacks on /admin.
     *
     * @return Finding
     */
    private function adminPath(): Finding
    {
        $frontName = (string) $this->deploymentConfig->get('backend/frontName');
        $useCustomUrl = $this->scopeConfig->isSetFlag('admin/url/use_custom_path');
        $customPath = trim((string) $this->scopeConfig->getValue('admin/url/custom_path'));
        $path = $useCustomUrl && $customPath !== '' ? $customPath : $frontName;
        if (in_array(strtolower($path), ['admin', 'backend', 'administrator', 'adminhtml'], true)) {
            return new Finding(
                'admin.path',
                Report::CATEGORY_ADMIN,
                Severity::MEDIUM,
                (string) __('The admin is at an easy-to-guess address (/%1)', $path),
                (string) __('Bots try /admin on every Magento store to guess passwords.'),
                (string) __('Run: bin/magento setup:config:set --backend-frontname="<a unique name>" and tell '
                    . 'your team the new admin URL.')
            );
        }
        return $this->passed('admin.path', Report::CATEGORY_ADMIN, __('The admin has a custom address'));
    }

    /**
     * Two-factor authentication for admin logins (PCI DSS 8.4).
     *
     * @return Finding
     */
    private function twoFactorAuth(): Finding
    {
        if ($this->moduleManager->isEnabled('Magento_TwoFactorAuth')) {
            return $this->passed('admin.2fa', Report::CATEGORY_ADMIN, __('Admin two-factor authentication is on'));
        }
        return new Finding(
            'admin.2fa',
            Report::CATEGORY_ADMIN,
            Severity::HIGH,
            (string) __('Two-factor authentication is switched off'),
            (string) __('Magento_TwoFactorAuth is disabled, so a stolen admin password is enough to log in. '
                . 'PCI DSS 8.4 requires multi-factor authentication for admin access.'),
            (string) __('Run: bin/magento module:enable Magento_TwoFactorAuth, '
                . 'then bin/magento setup:upgrade, and set up an authenticator app for each admin user.'),
            self::TFA_DOCS
        );
    }

    /**
     * HTTPS for the storefront and admin.
     *
     * @return Finding
     */
    private function https(): Finding
    {
        $problems = [];
        if (!$this->scopeConfig->isSetFlag('web/secure/use_in_adminhtml')) {
            $problems[] = (string) __('the admin does not use HTTPS');
        }
        foreach ($this->storeManager->getStores() as $store) {
            $id = (int) $store->getId();
            $secureUrl = (string) $this->scopeConfig->getValue('web/secure/base_url', ScopeInterface::SCOPE_STORE, $id);
            $unsecureUrl = (string) $this->scopeConfig->getValue(
                'web/unsecure/base_url',
                ScopeInterface::SCOPE_STORE,
                $id
            );
            $secureFrontend = $this->scopeConfig->isSetFlag(
                'web/secure/use_in_frontend',
                ScopeInterface::SCOPE_STORE,
                $id
            );
            if (!str_starts_with($secureUrl, 'https://') || !$secureFrontend) {
                $problems[] = (string) __('store view "%1" does not use HTTPS for secure pages', $store->getCode());
            } elseif (!str_starts_with($unsecureUrl, 'https://')) {
                $problems[] = (string) __('store view "%1" serves normal pages over HTTP', $store->getCode());
            }
        }
        if (!$problems) {
            return $this->passed('config.https', Report::CATEGORY_CONFIG, __('HTTPS is used everywhere'));
        }
        return new Finding(
            'config.https',
            Report::CATEGORY_CONFIG,
            Severity::HIGH,
            (string) __('Not every page uses HTTPS'),
            ucfirst(implode('; ', array_slice($problems, 0, 5))) . '.',
            (string) __('Set https:// base URLs and "Use Secure URLs" in Stores > Configuration > General > Web '
                . '(store view scope too), with a valid certificate.')
        );
    }

    /**
     * Active admin users with common usernames.
     *
     * @return Finding
     */
    private function adminUsernames(): Finding
    {
        try {
            $connection = $this->resource->getConnection();
            $select = $connection->select()
                ->from($this->resource->getTableName('admin_user'), ['username'])
                ->where('is_active = ?', 1)
                ->where('LOWER(username) IN (?)', self::COMMON_ADMIN_NAMES);
            $names = $connection->fetchCol($select);
        } catch (\Exception $e) {
            return $this->info('admin.usernames', Report::CATEGORY_ADMIN, __('Admin usernames not checked'));
        }
        if (!$names) {
            return $this->passed('admin.usernames', Report::CATEGORY_ADMIN, __('No admin user has a common username'));
        }
        return new Finding(
            'admin.usernames',
            Report::CATEGORY_ADMIN,
            Severity::MEDIUM,
            (string) __('Admin user with an easy-to-guess username'),
            (string) __('Active admin user(s): %1. Attackers try these names first.', implode(', ', $names)),
            (string) __('Create a personal admin account for each person, then deactivate or rename the shared one '
                . '(System > Permissions > All Users).')
        );
    }

    /**
     * Shared admin logins hide who did what (PCI DSS 8.2.2).
     *
     * @return Finding
     */
    private function accountSharing(): Finding
    {
        if (!$this->scopeConfig->isSetFlag('admin/security/admin_account_sharing')) {
            return $this->passed('admin.account_sharing', Report::CATEGORY_ADMIN, __('Admin account sharing is off'));
        }
        return new Finding(
            'admin.account_sharing',
            Report::CATEGORY_ADMIN,
            Severity::MEDIUM,
            (string) __('Admin account sharing is allowed'),
            (string) __('One admin login can be used from several places at once, so you cannot tell who did what. '
                . 'PCI DSS 8.2.2 does not allow shared accounts.'),
            (string) __('Set Stores > Configuration > Advanced > Admin > Security > Admin Account Sharing to No.')
        );
    }

    /**
     * Lock admin accounts after repeated failed logins (PCI DSS 8.3.4: at most 10 attempts).
     *
     * @return Finding
     */
    private function lockout(): Finding
    {
        $failures = (int) $this->scopeConfig->getValue('admin/security/lockout_failures');
        if ($failures > 0 && $failures <= 10) {
            return $this->passed(
                'admin.lockout',
                Report::CATEGORY_ADMIN,
                __('Admin accounts lock after %1 failed logins', $failures)
            );
        }
        return new Finding(
            'admin.lockout',
            Report::CATEGORY_ADMIN,
            $failures === 0 ? Severity::MEDIUM : Severity::LOW,
            $failures === 0
                ? (string) __('Admin accounts never lock after failed logins')
                : (string) __('Admin accounts lock only after %1 failed logins', $failures),
            (string) __('PCI DSS 8.3.4 asks for a lockout after no more than 10 failed attempts.'),
            (string) __('Set Maximum Login Failures to Lockout Account to 6 in Stores > Configuration > Advanced > '
                . 'Admin > Security.')
        );
    }

    /**
     * Idle admin sessions should end (PCI DSS 8.2.8: 15 minutes).
     *
     * @return Finding
     */
    private function sessionLifetime(): Finding
    {
        $seconds = (int) $this->scopeConfig->getValue('admin/security/session_lifetime');
        if ($seconds > 0 && $seconds <= 900) {
            return $this->passed(
                'admin.session_lifetime',
                Report::CATEGORY_ADMIN,
                __('Admin sessions end after %1 minutes', (int) ceil($seconds / 60))
            );
        }
        return new Finding(
            'admin.session_lifetime',
            Report::CATEGORY_ADMIN,
            Severity::LOW,
            (string) __('Admin sessions stay open for %1 minutes', (int) ceil(max($seconds, 0) / 60)),
            (string) __('PCI DSS 8.2.8 asks for idle sessions to end after 15 minutes.'),
            (string) __('Set Admin Session Lifetime (seconds) to 900 in Stores > Configuration > Advanced > Admin > '
                . 'Security.')
        );
    }

    /**
     * CAPTCHA on the admin login form slows down password guessing.
     *
     * @return Finding
     */
    private function adminCaptcha(): Finding
    {
        if ($this->scopeConfig->isSetFlag('admin/captcha/enable')) {
            return $this->passed('admin.captcha', Report::CATEGORY_ADMIN, __('CAPTCHA protects the admin login'));
        }
        return new Finding(
            'admin.captcha',
            Report::CATEGORY_ADMIN,
            Severity::LOW,
            (string) __('No CAPTCHA on the admin login'),
            (string) __('Without a CAPTCHA, bots can try passwords quickly.'),
            (string) __('Set Stores > Configuration > Advanced > Admin > CAPTCHA > Enable CAPTCHA in Admin to Yes.')
        );
    }

    /**
     * Secret keys in admin URLs protect against cross-site request forgery.
     *
     * @return Finding
     */
    private function secretKeyUrls(): Finding
    {
        if ($this->scopeConfig->isSetFlag('admin/security/use_form_key')) {
            return $this->passed('admin.secret_key', Report::CATEGORY_ADMIN, __('Admin URLs use secret keys'));
        }
        return new Finding(
            'admin.secret_key',
            Report::CATEGORY_ADMIN,
            Severity::MEDIUM,
            (string) __('Secret keys in admin URLs are switched off'),
            (string) __('Secret keys protect admin actions against cross-site request forgery (CSRF).'),
            (string) __('Set Stores > Configuration > Advanced > Admin > Security > Add Secret Key to URLs to Yes.')
        );
    }

    /**
     * Magento's Content Security Policy module (needed for PCI DSS 6.4.3 script control).
     *
     * @return Finding
     */
    private function contentSecurityPolicy(): Finding
    {
        if ($this->moduleManager->isEnabled('Magento_Csp')) {
            return $this->passed('config.csp', Report::CATEGORY_CONFIG, __('Content Security Policy is enabled'));
        }
        return new Finding(
            'config.csp',
            Report::CATEGORY_CONFIG,
            Severity::MEDIUM,
            (string) __('Content Security Policy is disabled'),
            (string) __('Magento_Csp controls which scripts may run. Without it, injected card skimmers run freely, '
                . 'and PCI DSS 6.4.3 is much harder to meet.'),
            (string) __('Run: bin/magento module:enable Magento_Csp, then bin/magento setup:upgrade.')
        );
    }

    /**
     * Template hints reveal file paths to visitors.
     *
     * @return Finding
     */
    private function templateHints(): Finding
    {
        foreach ($this->storeManager->getStores() as $store) {
            if ($this->scopeConfig->isSetFlag(
                'dev/debug/template_hints_storefront',
                ScopeInterface::SCOPE_STORE,
                (int) $store->getId()
            )) {
                return new Finding(
                    'config.template_hints',
                    Report::CATEGORY_CONFIG,
                    Severity::MEDIUM,
                    (string) __('Template hints are on'),
                    (string) __('Store view "%1" shows template paths on the storefront.', $store->getCode()),
                    (string) __('Run: bin/magento dev:template-hints:disable')
                );
            }
        }
        return $this->passed('config.template_hints', Report::CATEGORY_CONFIG, __('Template hints are off'));
    }

    /**
     * Cron runs security-related jobs (this check included).
     *
     * @return Finding
     */
    private function cron(): Finding
    {
        try {
            $connection = $this->resource->getConnection();
            $select = $connection->select()
                ->from($this->resource->getTableName('cron_schedule'), ['last' => 'MAX(finished_at)'])
                ->where('status = ?', 'success');
            $last = (string) $connection->fetchOne($select);
        } catch (\Exception $e) {
            return $this->info('config.cron', Report::CATEGORY_CONFIG, __('Cron status not checked'));
        }
        $now = (int) $this->dateTime->gmtTimestamp();
        if ($last !== '' && $now - (int) strtotime($last . ' UTC') <= 7200) {
            return $this->passed('config.cron', Report::CATEGORY_CONFIG, __('Cron is running'));
        }
        return new Finding(
            'config.cron',
            Report::CATEGORY_CONFIG,
            Severity::MEDIUM,
            (string) __('Cron is not running'),
            $last === ''
                ? (string) __('No cron job has ever finished successfully.')
                : (string) __('The last successful cron job finished at %1 UTC.', $last),
            (string) __('Run: bin/magento cron:install (as the web server user) and check the server crontab. '
                . 'Indexers, emails and scheduled security checks depend on cron.')
        );
    }

    /**
     * Passed finding.
     *
     * @param string $code
     * @param string $category
     * @param \Stringable|string $title
     * @return Finding
     */
    private function passed(string $code, string $category, \Stringable|string $title): Finding
    {
        return new Finding($code, $category, Severity::PASSED, (string) $title);
    }

    /**
     * Informational finding.
     *
     * @param string $code
     * @param string $category
     * @param \Stringable|string $title
     * @return Finding
     */
    private function info(string $code, string $category, \Stringable|string $title): Finding
    {
        return new Finding($code, $category, Severity::INFO, (string) $title);
    }
}

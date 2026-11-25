<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

/**
 * One result of a check: what was found, how serious it is and how to fix it.
 */
class Finding
{
    /**
     * @var string
     */
    private string $code;

    /**
     * @var string
     */
    private string $category;

    /**
     * @var string
     */
    private string $severity;

    /**
     * @var string
     */
    private string $title;

    /**
     * @var string
     */
    private string $detail;

    /**
     * @var string
     */
    private string $fix;

    /**
     * @var string
     */
    private string $link;

    /**
     * @param string $code Stable identifier, e.g. "magento_version.advisories"
     * @param string $category Group shown in the admin (see Category constants)
     * @param string $severity One of the Severity constants
     * @param string $title Short summary
     * @param string $detail What was found
     * @param string $fix How to fix it (empty for passed checks)
     * @param string $link Optional reference URL
     */
    public function __construct(
        string $code,
        string $category,
        string $severity,
        string $title,
        string $detail = '',
        string $fix = '',
        string $link = ''
    ) {
        $this->code = $code;
        $this->category = $category;
        $this->severity = isset(Severity::RANK[$severity]) ? $severity : Severity::INFO;
        $this->title = $title;
        $this->detail = $detail;
        $this->fix = $fix;
        $this->link = $link;
    }

    /**
     * Stable identifier.
     *
     * @return string
     */
    public function getCode(): string
    {
        return $this->code;
    }

    /**
     * Category code.
     *
     * @return string
     */
    public function getCategory(): string
    {
        return $this->category;
    }

    /**
     * Severity code.
     *
     * @return string
     */
    public function getSeverity(): string
    {
        return $this->severity;
    }

    /**
     * Short summary.
     *
     * @return string
     */
    public function getTitle(): string
    {
        return $this->title;
    }

    /**
     * What was found.
     *
     * @return string
     */
    public function getDetail(): string
    {
        return $this->detail;
    }

    /**
     * How to fix it.
     *
     * @return string
     */
    public function getFix(): string
    {
        return $this->fix;
    }

    /**
     * Reference URL, if any.
     *
     * @return string
     */
    public function getLink(): string
    {
        return $this->link;
    }

    /**
     * Whether this finding is a problem to fix.
     *
     * @return bool
     */
    public function isIssue(): bool
    {
        return isset(Severity::PENALTY[$this->severity]);
    }

    /**
     * Plain array for storage.
     *
     * @return array<string,string>
     */
    public function toArray(): array
    {
        return [
            'code' => $this->code,
            'category' => $this->category,
            'severity' => $this->severity,
            'title' => $this->title,
            'detail' => $this->detail,
            'fix' => $this->fix,
            'link' => $this->link,
        ];
    }
}

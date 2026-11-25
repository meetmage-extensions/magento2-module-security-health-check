<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Controller\Adminhtml\Report;

use Magento\Backend\App\Action;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Backend\Model\View\Result\Page;
use Magento\Framework\View\Result\PageFactory;

/**
 * System > Security Health Check: the latest report.
 */
class Index extends Action implements HttpGetActionInterface
{
    public const ADMIN_RESOURCE = 'MeetMage_SecurityHealthCheck::report';

    /**
     * @var PageFactory
     */
    private PageFactory $pageFactory;

    /**
     * @param Action\Context $context
     * @param PageFactory $pageFactory
     */
    public function __construct(Action\Context $context, PageFactory $pageFactory)
    {
        parent::__construct($context);
        $this->pageFactory = $pageFactory;
    }

    /**
     * Render the report page.
     *
     * @return Page
     */
    public function execute(): Page
    {
        /** @var Page $page */
        $page = $this->pageFactory->create();
        $page->setActiveMenu('MeetMage_SecurityHealthCheck::report');
        $page->getConfig()->getTitle()->prepend((string) __('Security Health Check'));
        return $page;
    }
}

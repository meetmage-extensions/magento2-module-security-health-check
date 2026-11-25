<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Controller\Adminhtml\Report;

use Magento\Backend\App\Action;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\Result\Redirect;
use MeetMage\SecurityHealthCheck\Model\Scanner;

/**
 * "Run check now" button (POST with the admin form key).
 */
class Run extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'MeetMage_SecurityHealthCheck::report';

    /**
     * @var Scanner
     */
    private Scanner $scanner;

    /**
     * @param Action\Context $context
     * @param Scanner $scanner
     */
    public function __construct(Action\Context $context, Scanner $scanner)
    {
        parent::__construct($context);
        $this->scanner = $scanner;
    }

    /**
     * Run the check and go back to the report.
     *
     * @return Redirect
     */
    public function execute(): Redirect
    {
        try {
            $report = $this->scanner->scan(true);
            $this->messageManager->addSuccessMessage((string) __(
                'Check finished: score %1/100, %2 issue(s) to fix.',
                $report->getScore(),
                count($report->getIssues())
            ));
        } catch (\Exception $e) {
            $this->messageManager->addErrorMessage((string) __('The check could not run: %1', $e->getMessage()));
        }
        return $this->resultRedirectFactory->create()->setPath('*/*/index');
    }
}

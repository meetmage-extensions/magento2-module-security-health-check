<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Source;

use Magento\Framework\Data\OptionSourceInterface;
use MeetMage\SecurityHealthCheck\Model\Config;

/**
 * Options for "When to Send".
 */
class Frequency implements OptionSourceInterface
{
    /**
     * Frequency options.
     *
     * @return array<int,array{value:string,label:\Magento\Framework\Phrase}>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => Config::FREQUENCY_NEW, 'label' => __('Only when new issues appear')],
            ['value' => Config::FREQUENCY_WEEKLY, 'label' => __('Weekly while issues are open')],
            ['value' => Config::FREQUENCY_DAILY, 'label' => __('Daily while issues are open')],
        ];
    }
}

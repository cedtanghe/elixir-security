<?php

namespace Elixir\Security\Firewall\Identity;

use Elixir\Security\Firewall\FirewallAbstract;
use Elixir\Security\Firewall\FirewallEvent;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Firewall extends FirewallAbstract
{
    /**
     * {@inheritdoc}
     */
    public function analyze($resource)
    {
        $this->sort();
        $resource = trim($resource, '/');

        $this->dispatch(new FirewallEvent(FirewallEvent::ANALYSE, ['ressource' => $resource]));

        foreach ($this->accessControls as $config) {
            $accessControl = $config['access_control'];

            if (preg_match($accessControl->getPattern(), $resource)) {
                $this->dispatch(
                    new FirewallEvent(
                        FirewallEvent::RESOURCE_MATCHED,
                        [
                            'ressource' => $resource,
                            'access_control' => $accessControl,
                        ]
                    )
                );

                $options = $accessControl->getOptions();
                $domains = (array) $options['domains'];
                $assert = $options['assert'];

                if (count($domains) === 0 || in_array(null, $domains, true)) {
                    $granted = true;

                    if (!empty($assert)) {
                        $granted = false;

                        if (true === call_user_func_array($assert, [['has_domain' => false, 'firewall' => $this]])) {
                            $granted = true;
                        }
                    }

                    if ($granted) {
                        // Access granted
                        $this->dispatch(
                            new FirewallEvent(
                                FirewallEvent::ACCESS_GRANTED,
                                [
                                    'ressource' => $resource,
                                    'access_control' => $accessControl,
                                ]
                            )
                        );

                        return true;
                    }
                }

                $domainFound = count($this->authManager->isEmpty()) === 0;

                if ($domainFound) {
                    foreach ($domains as $domain) {
                        if ($this->authManager->hasIdentity($domain)) {
                            $domainFound = true;
                            $granted = true;

                            if (!empty($assert)) {
                                $granted = false;

                                if (true === call_user_func_array($assert, [['has_domain' => true, 'firewall' => $this]])) {
                                    $granted = true;
                                }
                            }

                            if ($granted) {
                                // Access granted
                                $this->dispatch(
                                    new FirewallEvent(
                                        FirewallEvent::ACCESS_GRANTED,
                                        [
                                            'ressource' => $resource,
                                            'access_control' => $accessControl,
                                        ]
                                    )
                                );

                                return true;
                            }
                        }
                    }
                }

                if (!$domainFound) {
                    // No identity
                    $this->dispatch(
                        new FirewallEvent(
                            FirewallEvent::IDENTITY_NOT_FOUND,
                            [
                                'ressource' => $resource,
                                'access_control' => $accessControl,
                            ]
                        )
                    );
                } else {
                    // Forbidden
                    $this->dispatch(
                        new FirewallEvent(
                            FirewallEvent::ACCESS_FORBIDDEN,
                            [
                                'ressource' => $resource,
                                'access_control' => $accessControl,
                            ]
                        )
                    );
                }

                return false;
            }
        }

        // No access controls found
        $this->dispatch(new FirewallEvent(FirewallEvent::NO_ACCESS_CONTROLS_FOUND, ['ressource' => $resource]));

        return true;
    }
}

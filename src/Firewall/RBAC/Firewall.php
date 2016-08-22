<?php

namespace Elixir\Security\Firewall\RBAC;

use Elixir\Security\Firewall\FirewallAbstract;
use Elixir\Security\Firewall\FirewallEvent;
use Elixir\Security\RBAC\RBACInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Firewall extends FirewallAbstract
{
    /**
     * {@inheritdoc}
     *
     * @throws \LogicException
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
                $roles = (array) $options['roles'];
                $permissions = (array) $options['permissions'];
                $assert = $options['assert'];

                if (count($domains) === 0 || in_array(null, $domains, true)) {
                    $granted = true;

                    if (!empty($assert)) {
                        $granted = false;

                        if (true === call_user_func_array($assert, [['has_domain' => false, 'has_role' => false, 'has_permission' => false, 'firewall' => $this]])) {
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
                            if (count($roles) === 0) {
                                $granted = true;

                                if (!empty($assert)) {
                                    $granted = false;

                                    if (true === call_user_func_array($assert, [['has_domain' => true, 'has_role' => false, 'has_permission' => false, 'firewall' => $this]])) {
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

                            $domainFound = true;
                            $identity = $this->authManager->getIdentity($domain);
                            $context = $identity->getSecurityContext();

                            if (!$context instanceof RBACInterface) {
                                throw new \LogicException(sprintf('The security context of identity domain "%s" should be "Elixir\Security\RBAC\RBACInterface" type.', $domain));
                            }

                            if (count($permissions) == 0) {
                                $permissions = [null];
                            }

                            $a = function ($config) use ($assert) {
                                $config += ['has_domain' => true, 'firewall' => $this];

                                return call_user_func_array($assert, [$config]);
                            };

                            foreach ($roles as $role) {
                                foreach ($permissions as $permission) {
                                    if ($context->isGranted($role, $permission, $a)) {
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

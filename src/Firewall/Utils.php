<?php

namespace Elixir\Security\Firewall;

use Psr\Http\Message\ServerRequestInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Utils
{
    /**
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    public static function createResource(ServerRequestInterface $request)
    {
        $module = preg_replace('/[^a-z0-9]+/i', '', $request->getAttribute('module'));
        $controller = preg_replace('/[^a-z0-9]+/i', '', $request->getAttribute('controller'));
        $action = preg_replace('/[^a-z0-9]+/i', '', $request->getAttribute('action'));

        if (!$module || !$controller || !is_string($controller) || !$action) {
            return '';
        }

        if (false !== strpos($module, '(@') && preg_match('/\(@([^\)]+)\)/', $module, $matches)) {
            $module = $matches[1];
        }

        return strtoupper(sprintf('%s_%s_%s', $module, $controller, $action));
    }
}

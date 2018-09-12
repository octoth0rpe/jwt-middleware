<?php declare(strict_types=1);

namespace JWTMiddleware;

use Psr\Container\ContainerInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Firebase\JWT\JWT;

/**
 * PSR-15 middleware implementation that decodes a JWT found in the request
 * headers, and adds the claims to a PSR-11 container before the request is
 * handled. After the request has been handled, it generates a new token with
 * any changes to the claims made during the handling of the request, and with
 * an updated expiration time and adds the new JWT to the response headers.
 */
class Middleware implements MiddlewareInterface
{
    /* The container to put the UserToken into */
    protected $container;

    /* The default claims if a token isn't found in the request or is invalid */
    protected $defaultClaims;

    /* The key used to encrypt the token */
    protected $key;

    /* How many seconds the token should be valid for */
    protected $expiresInSeconds;

    /**
     * Constructs the Middleware class. Note that this catches _all_ exceptions
     * thrown by Firebase\JWT\JWT. If any kind of problem occurs when processing
     * a token, the middleware simply issues a new token with the configured
     * default claims.
     * 
     * @param ContainerInterface $container The PSR-11 container into which a
     *                                      UserToken object will be added                                 
     * @param array $defaultClaims The default claims that will be in a newly
     *                             created UserToken
     * @param string $key The key used to sign the JWT
     * @param int $expiresInSeconds How many seconds an issued token should be
     *                              valid for, defaults to 1200 (20 minutes)
     */
    public function __construct(
        ContainerInterface $container,
        array $defaultClaims = [],
        string $key = null,
        int $expiresInSeconds = 1200
    ) {
        $this->container = $container;    
        $this->defaultClaims = $defaultClaims;    
        $this->key = $key;    
        $this->expiresInSeconds = $expiresInSeconds;    
    }

    /**
     * Decodes a valid JWT in the headers and adds a UserToken to the container,
     * passes the request to the request handler, and then adds a refreshed
     * jwt to the response headers with an updated expiration time.
     */
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ) : ResponseInterface {
        # Find the token in the headers, defaulting to a blank string
        $serverParameters = $request->getServerParams();
        $authHeader = $serverParameters['HTTP_AUTHORIZATION'] ?? '';
        $token = str_replace('Bearer ', '', $authHeader);

        # There are 3 conditions where we'll need to make a new token:
        # * If there's no token found
        # * If the token found is expired
        # * If the token found is invalid
        $requireNew = true;

        # If we found a token, then decode it and add its contents to the
        # container.
        if ($token !== '') {
            try {
                $claims = JWT::decode($token, $this->key, array('HS256'));
                $token = new UserToken((array) $claims);
                $this->container->add('JWTMiddleware\UserToken', $token);
                $requireNew = false;
            } 
            catch (\Exception $e) {
                # If anything went wrong with processing the token, then we
                # don't need to do anything as $requireNew is still set to true.
                # TODO: maybe do something with the exception?
            }
        }

        # If no token was found or it couldn't be used, then create a new 
        # UserToken using the default claims, and add it to the container.
        if ($requireNew) {
            $token = new UserToken($this->defaultClaims);
            $this->container->add('JWTMiddleware\UserToken', $token);
        }

        $response = $handler->handle($request);

        # Now the that request has been handled, we need to create a new token
        # that includes any changes to the token claims and add it as a response
        # header.
        $nextClaims = $this->container
            ->get('JWTMiddleware\UserToken')
            ->getNextClaims(time() + $this->expiresInSeconds);
        $nextToken = JWT::encode($nextClaims, $this->key);
        return $response->withHeader('Authorization', 'Bearer '.$nextToken);
    }
}

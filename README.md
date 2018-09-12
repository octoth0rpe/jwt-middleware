# jwt-middleware
A PSR-15 middleware that handles json web tokens by decoding them (using firebase/php-jwt) and writing the decoded token to a PSR-11 container.

Here's an example of how you can use this using Container and Route from
theleague:
```
# Setup the DI container w/ autowiring
$container = new League\Container\Container;
$container->delegate(new League\Container\ReflectionContainer());

# Setup the router and wiring strategy
$strategy = (new League\Route\Strategy\ApplicationStrategy)->setContainer($container);
$router   = (new League\Route\Router)->setStrategy($strategy);

# Setup middleware that will populate the UserToken key in the container with
# claims from valid JWTs. This will issue a refreshed JWT with every request
$router->middleware(new Middleware(
    $container,
    [ 'id' => 0 ],
    'mysecretjwtkey'
));
````

<?php

/** @var Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

use App\Http\Controllers\CognitoController;
use Laravel\Lumen\Routing\Router;

$router->post('/create', 'CognitoController@register');
$router->post('/login', 'CognitoController@login');
$router->post('/force-password-change', 'CognitoController@forcePasswordChange');
$router->post('/forgot-password', 'CognitoController@forgetPassword');
$router->post('/reset-password', 'CognitoController@resetPassword');

$router->get('/', function () use ($router) {
    return $router->app->version();
});

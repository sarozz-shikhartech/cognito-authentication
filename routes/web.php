<?php

/** @var Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

use Laravel\Lumen\Routing\Router;

$router->post('/app/login', 'AuthController@userLogin');
$router->post('/app/register', 'AuthController@userRegister');

$router->group(['middleware' => 'auth'], function () use ($router) {
    $router->post('/cognito/create', 'CognitoController@createPool');
    $router->post('/cognito-user/create', 'CognitoController@register');
    $router->post('/cognito-user/login', 'CognitoController@login');
    $router->post('/cognito-user/force-password-change', 'CognitoController@forcePasswordChange');
    $router->post('/cognito-user/forgot-password', 'CognitoController@forgetPassword');
    $router->post('/cognito-user/reset-password', 'CognitoController@resetPassword');
});

$router->get('/', function () use ($router) {
    return $router->app->version();
});

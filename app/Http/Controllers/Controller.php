<?php

namespace App\Http\Controllers;

use App\Http\ResponseTrait;
use App\Http\Services\CognitoService;
use App\Http\Services\MainService;
use Laravel\Lumen\Routing\Controller as BaseController;

class Controller extends BaseController
{
    use ResponseTrait;
    protected CognitoService $cognitoService;
    protected MainService $mainService;

    /**
     * @param CognitoService $cognitoService
     * @param MainService $mainService
     */
    public function __construct(CognitoService $cognitoService, MainService $mainService)
    {
        $this->cognitoService = $cognitoService;
        $this->mainService = $mainService;
    }


}

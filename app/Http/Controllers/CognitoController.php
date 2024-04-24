<?php

namespace App\Http\Controllers;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Result;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

class CognitoController extends Controller
{

    /**
     * @param Request $request
     * @return JsonResponse
     *
     * @throws ValidationException
     */
    public function createPool(Request $request): JsonResponse
    {
        $this->validate($request, [
            'storeName' => 'required',
            'storeId'   => 'required|int'
        ]);

        $storeName = $request->get('storeName');
        $storeId = $request->get('storeId');

        /*
         * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html
         */
        try {
            $client = $this->cognitoService->connectCognito();
            $result = $client->createUserPool([
                //name of the pool i.e. pool-1-testStore-1123456
                'PoolName' => 'pool-'. $storeId . '-' . $storeName . '-' . time(),
                //configuration for admin of this pool
                'AdminCreateUserConfig' => [
                    //if true then only the admin is allowed to create user profiles. set to false if users can sign themselves up via an app
                    'AllowAdminCreateUserOnly' => true,
                ],
                //policies associated with the new user pool
                'Policies' => [
                    //rules for users password requirement
                    'PasswordPolicy' => [
                        'MinimumLength' => 8, //required least minimum of 8 words in password
                    ],
                ],
                //array of schema attributes for the new user pool. moreover like columns in database table
                'Schema' => [
                    [
                        'AttributeDataType' => 'String', //datatype that the field will hold
                        'Mutable' => true, //is it editable
                        'Name' => 'store_name',//field name
                        'Required' => false, //nullable or not
                    ],
                    [
                        "AttributeDataType" => "String",
                        "Mutable" => false, //false which means it cannot be updated once set
                        "Name" => "email",
                        "Required" => true,
                    ]
                ],
                "UsernameConfiguration" => [
                    "CaseSensitive" => false
                ],
                //Specifies whether a user can use an email address or phone number as a username when they sign up.
                "UsernameAttributes" => ["email"],
            ]);

            $userPoolId = $result['UserPool']['Id'];

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html
             */
            $result = $client->createUserPoolClient([
                //name of the client
                'ClientName' => 'client-' . $storeId . '-' . $storeName . '-' . time(),
                'UserPoolId' => $userPoolId,
                //desired authentication flows that user pool client to support.
                'ExplicitAuthFlows' => [
                    'ALLOW_ADMIN_USER_PASSWORD_AUTH', //Enable admin based user password authentication flow
                    'ALLOW_CUSTOM_AUTH', //Enable Lambda trigger based authentication.
                    'ALLOW_USER_SRP_AUTH', //Enable SRP-based authentication.
                    'ALLOW_REFRESH_TOKEN_AUTH', //Enable auth-flow to refresh tokens.
                ],
                //config to specify whether you want to generate a secret for the user pool client being created.
                'GenerateSecret' => false,
                'RefreshTokenValidity' => 30,
                //if ENABLED and user doesn't exist, then authentication returns an error indicating either the username or password was incorrect. else in LEGACY, returns a UserNotFoundException exception
                'PreventUserExistenceErrors' => 'ENABLED'
            ]);

            $clientId = $result['UserPoolClient']['ClientId'];

            return $this->output('Pool and Client ID created.', [
                'poolId' => $userPoolId,
                'clientId' => $clientId
            ]);
        } catch (CognitoIdentityProviderException $exception) {
            return $this->output('Pool create request failed.', $exception->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * @param Request $request
     * @return JsonResponse|\Exception|array
     * @throws ValidationException
     */
    public function login(Request $request): JsonResponse|\Exception|array
    {
        $this->validate($request, [
            'email' => 'required',
            'password'   => 'required'
        ]);

        $email = $request->email;
        $password = $request->password;
        if (empty($email) || empty($password)) {
            return $this->output('Email or Password is invalid.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $response = $this->cognitoService->processCognitoAuthenticate($request);
        if ($response instanceof CognitoIdentityProviderException) {
            return $this->output('User not found.', $response->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        if (array_key_exists('cognito_session', $response)) {
            return $this->output('Temporary Password Change Required.', $response, ResponseAlias::HTTP_ACCEPTED);
        }

        return $this->output('Authenticated.', $response);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function register(Request $request): JsonResponse
    {
        $name = $request->name ?? null;
        $email = $request->email ?? null;
        if (empty($name)) {
            return $this->output('Name field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }
        if (empty($email)) {
            return $this->output('Email field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $cognitoResponse = $this->cognitoService->processCognitoAdminCreateUser($request);
        if (!$cognitoResponse instanceof Result) {
            return $this->output('Could not proceed with register.', $cognitoResponse->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        $cognitoSubIndex = array_search("sub", array_column($cognitoResponse->get('User')["Attributes"], "Name"));
        $newUser = [
            'name' => $name,
            'email' => $email,
            'cognito_username' => $cognitoResponse->get('User')['Username'],
            'cognito_id' => $cognitoResponse->get('User')['Attributes'][$cognitoSubIndex]['Value']
        ];

        return $this->output('User Created. Email has been sent to respective email.', $newUser);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function changePassword(Request $request): JsonResponse
    {
        $email = $request->email ?? null;
        $newPassword = $request->password ?? null;
        if (empty($newPassword)) {
            return $this->output('Password field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }
        if (empty($email)) {
            return $this->output('Email field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $res = $this->cognitoService->processCognitoUserPasswordChange($request);
        if ($res instanceof CognitoIdentityProviderException || $res != 200) {
            return $this->output('Password change failed.', $res->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $this->output('Password update successful.');
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function forgetPassword(Request $request): JsonResponse
    {
        $email = $request->email ?? null;
        if (empty($email)) {
            return $this->output('Email field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $res = $this->cognitoService->processForgetPassword($request);

        if ($res) {
            return $this->output('Success, we have forwarded password reset code to the respective mail.');
        } else {
            return $this->output('Forget password process failed.', [], ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * @param Request $request
     * @return CognitoIdentityProviderException|\Exception|JsonResponse
     */
    public function forcePasswordChange(Request $request): JsonResponse|\Exception|CognitoIdentityProviderException
    {
        $email = $request->email ?? null;
        $password = $request->password ?? null;
        $cognito_session = $request->cognito_session ?? null;

        $awsClientId = $request->headers->get('aws_client_id');

        if (empty($email) || empty($password) || empty($cognito_session)) {
            return $this->output('Invalid request data.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $params = [
            'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
            'ClientId' => $awsClientId,
            'ChallengeResponses' => [
                'USERNAME' => $email,
                'NEW_PASSWORD' => $password
            ],
            'Session' => $cognito_session
        ];

        $res = $this->cognitoService->processCognitoForcePasswordChange($params);

        if ($res instanceof CognitoIdentityProviderException) {
            return $this->output('Force password change process failed.', $res->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $this->output('Password changed successfully.', $res);
    }

    public function resetPassword(Request $request): JsonResponse
    {
        $email = $request->email ?? null;
        $password = $request->password ?? null;
        $code = $request->code ?? null;
        if (empty($email) || empty($password) || empty($code)) {
            return $this->output('Invalid request data.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $res = $this->cognitoService->processResetPassword($request);

        if ($res instanceof CognitoIdentityProviderException) {
            return $this->output('Force password change process failed.', $res->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $this->output('Password changed successfully.', $res);

    }
}

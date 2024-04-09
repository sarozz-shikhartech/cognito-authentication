<?php

namespace App\Http\Services;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Credentials\Credentials;
use Illuminate\Support\Str;

class CognitoService extends MainService
{

    public function connectCognito(): CognitoIdentityProviderClient|\Exception|CognitoIdentityProviderException
    {
        try {
            return new CognitoIdentityProviderClient([
                'version'     => 'latest',
                'region'      => 'us-west-1',
                'credentials' => new Credentials(env('AWS_ACCESS_KEY'), env('AWS_SECRET_KEY'))
            ]);

        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }
    }

    public function processCognitoAuthenticate($request): \Exception|array
    {
        try {
            $email = $request->email;
            $password = $request->password;

            $headers = $request->headers;
            $awsCognitoPoolId = $headers->get('aws_cognito_pool_id');
            $awsClientId = $headers->get('aws_client_id');

            $client = $this->connectCognito();

            $response = $client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => trim($email),
                    'PASSWORD' => trim($password)
                ],
                'ClientId' => $awsClientId,
                'UserPoolId' => $awsCognitoPoolId
            ]);

            $response = $response->toArray();

            if (array_key_exists('ChallengeName', $response) && $response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED') {
                return ['cognito_session' => $response['Session'], 'email' => $email];
            }

            $idToken = $response['AuthenticationResult']['IdToken'];

            // Get user information from idToken
            $payload = explode('.', $idToken)[1];
            $decodedPayload = base64_decode($payload);
            $userData = json_decode($decodedPayload);
            $cognitoUsername = $userData->{'cognito:username'};

            return ['cognito_username' => $cognitoUsername];
        } catch (\Exception $exception) {
            return $exception;
        }
    }

    public function processCognitoAdminCreateUser($request)
    {
        try {
            $name = $request->name;
            $email = $request->email;
            $email_verified = $request->email_verified ?? "false";

            $headers = $request->headers;
            $awsCognitoPoolId = $headers->get('aws_cognito_pool_id');

            $client = $this->connectCognito();

            return $client->adminCreateUser([
                "DesiredDeliveryMediums" => ["EMAIL"],
                "TemporaryPassword" => Str::password(12),
                "UserAttributes" => [
                    ["Name" => "name", "Value" => $name],
                    ["Name" => "email", "Value" => $email],
                    ["Name" => "email_verified", "Value" => $email_verified],
                ],
                "Username" => $email,
                "UserPoolId" => $awsCognitoPoolId,
            ]);

        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }
    }

    public function processCognitoUserPasswordChange($request)
    {
        try {
            $email = $request->email;
            $currentPassword = $request->current_password;
            $newPassword = $request->new_password;

            $client = $this->connectCognito();

            $payload = [
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $currentPassword,
                ],
                'ClientId' => '',
                'UserPoolId' => '',
            ];
            $response = $client->adminInitiateAuth($payload);

            // Extract tokens from callback request
            $accessToken = $response->toArray()['AuthenticationResult']['AccessToken'];

            $response = $client->changePassword([
                'AccessToken' => $accessToken,
                'PreviousPassword' => $currentPassword,
                'ProposedPassword' => $newPassword,
            ]);

            return $response->toArray()['@metadata']['statusCode'];

        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }
    }

    public function processForgetPassword($request): bool
    {
        try {
            $headers = $request->headers;
            $awsClientId = $headers->get('aws_client_id');

            $client = $this->connectCognito();
            $params = [
                "ClientId" => $awsClientId,
                "Username" => $request->email,
            ];

            $client->forgotPassword($params);

            return true;
        } catch (CognitoIdentityProviderException $exception) {
            return false;
        }
    }

    public function processCognitoForcePasswordChange($params = [])
    {
        try {
            $client = $this->connectCognito();

            $response = $client->respondToAuthChallenge($params);
            $response = $response->toArray();

            // Extract tokens from callback request
            $idToken = $response['AuthenticationResult']['IdToken'];

            // Get user information from idToken
            $payload = explode('.', $idToken)[1];
            $decodedPayload = base64_decode($payload);
            $userData = json_decode($decodedPayload);
            return $userData->{'cognito:username'};
        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }

    }

    public function processResetPassword($request): CognitoIdentityProviderClient|\Exception|string|CognitoIdentityProviderException
    {
        try {
            $headers = $request->headers;
            $awsClientId = $headers->get('aws_client_id');

            $client = $this->connectCognito();

            $params = [
                'ClientId' => $awsClientId,
                'Username' => $request->email,
                'Password' => $request->password,
                'ConfirmationCode' => $request->code
            ];

            $client->confirmForgotPassword($params);
            return $client;
        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }

    }
}

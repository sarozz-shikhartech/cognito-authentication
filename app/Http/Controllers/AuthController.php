<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

class AuthController extends Controller
{
    public function userLogin(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent());

        $email = $data->email ?? null;
        $password = $data->password ?? null;
        if (empty($email) || empty($password)) {
            return $this->output('Email and password is required.', []);
        }

        $user = User::where('email', '=', $email)->first();
        if (!$user) {
            return $this->output('User not found', [], ResponseAlias::HTTP_UNAUTHORIZED);
        }

        $credentials = $request->only('email', 'password');
        $token = Auth::claims(['user_id' => $user->id, 'email' => $user->email])->attempt($credentials);
        if (!$token) {
            return $this->output('Invalid Credentials.', [], ResponseAlias::HTTP_UNAUTHORIZED);
        }

        return $this->output('Login Successfully', [
            'email' => $user->email,
            'name' => $user->name,
            'token' => $token
        ]);
    }

    public function userRegister(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent());

        $name = $data->name ?? null;
        $email = $data->email ?? null;
        $password = $data->password ?? null;
        if (empty($email) || empty($password) || empty($name)) {
            return $this->output('Email, Name and Password is required.', []);
        }

        try {
            $newUser = User::create([
                'name'       => $name,
                'email'      => $email,
                'password'   => Hash::make($password),
                'status'     => '1'
            ]);

            return $this->output('User created successfully.', $newUser);
        } catch (\Exception $exception) {
            return $this->output('Registration failed.', $exception->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

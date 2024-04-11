<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

class AuthController extends Controller
{
    /**
     * @throws ValidationException
     */
    public function userLogin(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent());

        $this->validate($request, [
            'email' => 'required',
            'password' => 'required'
        ]);

        $user = User::where('email', '=', $data->email)->first();
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

    /**
     * @throws ValidationException
     */
    public function userRegister(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent());

        $this->validate($request, [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required'
        ]);

        $name = $data->name;
        $email = $data->email;
        $password = $data->password;

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

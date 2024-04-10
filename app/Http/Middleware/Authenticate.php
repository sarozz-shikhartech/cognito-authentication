<?php

namespace App\Http\Middleware;

use App\Http\ResponseTrait;
use App\Models\User;
use Closure;
use Illuminate\Contracts\Auth\Factory as Auth;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Token;
use Symfony\Component\HttpFoundation\Response;

class Authenticate
{
    use ResponseTrait;

    /**
     * The authentication guard factory instance.
     *
     * @var Auth
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param Auth $auth
     * @return void
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param  \Closure  $next
     * @param string|null $guard
     * @return mixed
     */
    public function handle(Request $request, Closure $next, string $guard = null): mixed
    {
        if ($request->header('authorization') && !empty($request->header('authorization'))) {
            $jwtToken = trim(str_replace("Bearer", "", $request->headers->get('Authorization')));
            try {
                $decodedToken = JWTAuth::manager()->decode(new Token($jwtToken));

                $user = User::where(['email' => $decodedToken['email'], 'id' => $decodedToken['user_id'], 'status' => '1'])->first();

                //if member not found return unauthorized error
                if (!$user instanceof User) {
                    return $this->output('Invalid Access', [], Response::HTTP_UNAUTHORIZED);
                }

                //if valid member found the add id and email in event request
                $request->attributes->set('user', [
                    'id' => $user->id,
                    'email' => $user->email,
                    'name' => $user->name,
                ]);

                return $next($request);

            } catch (\Exception $exception) {
                return $this->output('Invalid or Expired Token', [], Response::HTTP_UNAUTHORIZED);
            }
        }

        return $this->output('No JWT Token', [], Response::HTTP_UNAUTHORIZED);
    }
}

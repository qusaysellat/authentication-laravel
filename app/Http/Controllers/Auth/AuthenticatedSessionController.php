<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Session;
use Inertia\Inertia;
use Inertia\Response;

class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     */
    public function create(): Response
    {
        return Inertia::render('Auth/Login', [
            'canResetPassword' => Route::has('password.request'),
            'status' => session('status'),
        ]);
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request): RedirectResponse
    {
        // if the user is the admin, it is ok to sign in on multiple devices
        if($request['email'] == 'admin@gmail.com') {
            $request->authenticateAdmin();

            $request->session()->regenerate();

            $user = Auth::user();

            $user->session_id = Session::getId();

            $user->save();

            return redirect()->intended(RouteServiceProvider::HOME);
        }

        else {

            // otherwise, it is up to the user to decide:

            // if sign out should be done on other devices
            $logout_others = (boolean)$request['logout_others'];

            // if so,
            if($logout_others) {
                $request->authenticate();

                // sign out of other devices and regenerate the session
                Auth::logoutOtherDevices($request['password']);

                $request->session()->regenerate();

                $user = Auth::user();

                $user->session_id = Session::getId();

                $user->save();

                return redirect()->intended(RouteServiceProvider::HOME);
            }
            // else if the user wants to keep remote sessions
            else {
                $is_logged1 = (boolean)User::where('email', $request['email'])->whereNotNull('remember_token')->count();
                $is_logged2 = (boolean)User::where('email', $request['email'])->whereNotNull('session_id')->count();

                if($is_logged1||$is_logged2) {
                    // don't allow the user to log in if the user is already logged in on other device

                    return redirect()->route('logged');
                }
                // only allow the user to log in if no other session is open elsewhere
                else {
                    $request->authenticate();

                    $request->session()->regenerate();

                    $user = Auth::user();

                    $user->session_id = Session::getId();

                    $user->save();

                    return redirect()->intended(RouteServiceProvider::HOME);
                }
            }

        }


    }

    public function logged() {
        // redirect the user to a page where a message points out that multiple sign in is not allowed
        return Inertia::render('Auth/Logged');
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): RedirectResponse
    {
        $user = User::find(Auth::user()->id);

        Auth::guard('web')->logout();


        // after log out, clear all session and token information

        $user->remember_token = null;
        $user->session_id = null;
        $user->save();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }
}

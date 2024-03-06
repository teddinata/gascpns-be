<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use App\Helpers\ResponseFormatter;
use Laravel\Fortify\Rules\Password;


class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            // Validasi input
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'phone' => ['nullable', 'string', 'max:255'],
                'password' => ['required', 'string', 'min:8', 'confirmed', new Password],
                'password_confirmation' => ['required', 'string', 'min:8'],
            ]);

            // Check email existence
            if (User::where('email', $request->email)->exists()) {
                throw ValidationException::withMessages([
                    'email' => ['Email is already taken. Please choose another.']
                ]);
            }

            // Creating or getting a new user
            $user = User::firstOrCreate(
                ['email' => $request->email],
                [
                    'name' => $request->name,
                    'username' => $request->username,
                    'phone' => $request->phone,
                    'password' => Hash::make($request->password),
                    'roles' => 'user',
                ]
            );

            // Creating a token for the newly created user
            $tokenResult = $user->createToken('authToken')->plainTextToken;

            // Returning user and token data to the client
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user,
            ], 'User registered successfully');

        } catch (ValidationException $e) {
            // Handling validation errors
            $errors = $e->errors();
            return ResponseFormatter::error([
                'message' => 'Validation failed',
                'errors' => $errors,
            ], 'Authentication Failed', 422);

        } catch (\Exception $e) {
            // Handling other exceptions
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $e->getMessage(),
            ], 'Authentication Failed', 500);
        }
    }

    // end point check user
    public function fetch(Request $request)
    {
        // check user with role admin
        $user = User::where('roles', 'admin')->get();
        return ResponseFormatter::success(
            $user,'Data user berhasil diambil');
    }
}

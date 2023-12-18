<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Facades\Hash;
use Error;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $validator = $this->validateDataUser($request);

            if ($validator->fails()) {
                return response()->json(
                    [
                        "success" => false,
                        "message" => "Error creating user",
                        "error" => $validator->errors()
                    ],
                    Response::HTTP_BAD_REQUEST
                );
            }

            $newUser = User::create(
                [
                    "name" => $request->input('name'),
                    "username" => $request->input('username'),
                    "email" => $request->input('email'),
                    "password" => bcrypt($request->input('password'))
                ]
            );

            return response()->json(
                [
                    "success" => true,
                    "message" => "User registered",
                    "data" => $newUser
                ],
                Response::HTTP_CREATED
            );
        } catch (\Throwable $th) {
            Log::error($th->getMessage());

            return response()->json(
                [
                    "success" => false,
                    "message" => "Error registering user"
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    private function validateDataUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|min:3|max:20',
            'username' => 'required|unique:users|min:3|max:12',
            'email' => 'required|unique:users|email',
            'password' => 'required|min:6|max:12',
        ]);

        return $validator;
    }

    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    "success" => false,
                    "message" => "Error login user",
                    "error" => $validator->errors()
                ], Response::HTTP_BAD_REQUEST);
            }

            $user = User::where('email', $request->input('email'))->first();

            if (!$user || !Hash::check($request->input('password'), $user->password)) {
                return response()->json([
                    "success" => false,
                    "message" => "Email or password are invalid"
                ], Response::HTTP_NOT_FOUND);
            }

            $token = $user->createToken('apiToken')->plainTextToken;

            return response()->json([
                "success" => true,
                "message" => "User Logged",
                "token" => $token,
                "data" => $user
            ]);
        } catch (\Throwable $th) {
            Log::error($th->getMessage());

            if ($th->getMessage() === 'Email or password are invalid') {
                return response()->json([
                    "success" => false,
                    "message" => "Email or password are invalid"
                ], Response::HTTP_NOT_FOUND);
            }

            return response()->json([
                "success" => false,
                "message" => "Error login user"
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

}

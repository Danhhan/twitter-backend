import { JwtPayload } from 'jsonwebtoken'
import { ParamsDictionary } from 'express-serve-static-core'

export interface RegisterReqBody {
  name: string
  email: string
  date_of_birth: Date
  password: string
  confirm_password: string
  avatar: string
}
export interface LoginReqBody {
  email: string
  password: string
}

export interface TokenPayload extends JwtPayload {
  user_id: string
  token_type: string
}

export interface LogoutRequestBody {
  refresh_token: string
}
export interface VerifyEmailRequestBody {
  email_verify_token: string
}

export interface ForgotPasswordRequestBody {
  email: string
}

export interface ResetPasswordRequestBody {
  forgot_password_token: string
  password: string
  confirm_password: string
}

export interface UpdateMeRequestBody {
  name?: string
  date_of_birth?: string
  bio?: string
  location?: string
  website?: string
  username?: string
  avatar?: string
  cover_photo?: string
}

export interface FollowRequestBody {
  follow_user_id: string
}

export interface UnfollowRequestParams extends ParamsDictionary {
  user_id: string
}

export interface ProfileRequestParams extends ParamsDictionary {
  username: string
}

export interface ChangePasswordRequestBody {
  old_password: string
  password: string
  confirm_password: string
}

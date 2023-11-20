import { Request, Response } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { pick, omit } from 'lodash'
import { ObjectId } from 'mongodb'
import { UserVeriFyStatus } from '~/constants/enum'
import httpStatus from '~/constants/httpStatus'
import { userMessages } from '~/constants/message'
import {
  LoginReqBody,
  LogoutRequestBody,
  RegisterReqBody,
  TokenPayload,
  VerifyEmailRequestBody,
  ForgotPasswordRequestBody,
  ResetPasswordRequestBody,
  UpdateMeRequestBody,
  FollowRequestBody,
  UnfollowRequestParams,
  ProfileRequestParams,
  ChangePasswordRequestBody
} from '~/models/requests/User.requests'
import { User } from '~/models/schema/User.schema'
import databaseService from '~/services/database.services'
import usersService from '~/services/users.services'

export const registerController = async (req: Request<ParamsDictionary, any, RegisterReqBody>, res: Response) => {
  const result = await usersService.register({ ...req.body })
  return res.json({
    message: userMessages.REGISTER_SUCCESS,
    result
  })
}
export const loginController = async (req: Request<ParamsDictionary, any, LoginReqBody>, res: Response) => {
  const result = await usersService.login({ ...req.body })
  return res.json({
    message: userMessages.LOGIN_SUCCESS,
    result
  })
}
export const logoutController = async (req: Request<ParamsDictionary, any, LogoutRequestBody>, res: Response) => {
  const { refresh_token } = req.body
  const result = await usersService.logout(refresh_token)

  return res.json(result)
}
export const verifyEmailController = async (
  req: Request<ParamsDictionary, any, VerifyEmailRequestBody>,
  res: Response
) => {
  const { user_id } = req.decoded_email_verify_token as TokenPayload
  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
  if (!user) {
    return res.status(httpStatus.NOT_FOUND).json({
      message: userMessages.USER_NOT_FOUND
    })
  }
  if (user.email_verify_token === '') {
    return res.json({
      message: userMessages.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }
  const result = await usersService.verifyEmail(user_id)
  return res.json({
    message: userMessages.EMAIL_VERIFIED_SUCCESS,
    result
  })
}
export const resendVerifyEmailController = async (req: Request<ParamsDictionary, any, any>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
  console.log('user: ', user)
  if (!user) {
    return res.status(httpStatus.NOT_FOUND).json({
      message: userMessages.USER_NOT_FOUND
    })
  }
  if (user.verify === UserVeriFyStatus.Verified) {
    return res.json({
      message: userMessages.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }
  const result = await usersService.resendVerifyEmail(user_id)
  return res.json({
    message: userMessages.RESEND_VERIFY_EMAIL_SUCCESS,
    result
  })
}

export const forgotPasswordController = async (
  req: Request<ParamsDictionary, any, ForgotPasswordRequestBody>,
  res: Response
) => {
  const { _id, verify } = req.user as User
  const result = await usersService.forgotPassword({ user_id: (_id as ObjectId).toString(), verify })
  return res.json({
    message: userMessages.CHECK_EMAIL_TO_RESET_PASSWORD,
    result
  })
}
export const verifyForgotPasswordTokenController = async (req: Request<ParamsDictionary, any, any>, res: Response) => {
  return res.json({
    message: userMessages.VERIFY_FORGOT_PASSWORD_TOKEN_SUCCESS
  })
}

export const resetPasswordTokenController = async (
  req: Request<ParamsDictionary, any, ResetPasswordRequestBody>,
  res: Response
) => {
  const { user_id } = req.decoded_forgot_password_token as TokenPayload
  const { password } = req.body
  const result = await usersService.resetPassword(user_id, password)
  return res.json({
    message: userMessages.RESET_PASSWORD_SUCCESS,
    result
  })
}

export const getMeController = async (req: Request<ParamsDictionary, any, any>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const user = await usersService.getMe(user_id)
  return res.json({
    message: userMessages.GET_ME_SUCCESS,
    result: user
  })
}
export const getProfileController = async (
  req: Request<ParamsDictionary, any, ProfileRequestParams>,
  res: Response
) => {
  const { username } = req.params
  const user = await usersService.getProfile(username)
  return res.json({
    message: userMessages.GET_PROFILE_SUCCESS,
    result: user
  })
}

export const updateMeController = async (req: Request<ParamsDictionary, any, UpdateMeRequestBody>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const { body } = req
  const user = await usersService.updateMe(user_id, body)
  return res.json({
    message: userMessages.UPDATE_ME_SUCCESS,
    result: user
  })
}

export const followController = async (req: Request<ParamsDictionary, any, FollowRequestBody>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const { follow_user_id } = req.body
  const result = await usersService.follow(user_id, follow_user_id)
  return res.json({
    result
  })
}

export const unfollowController = async (req: Request<ParamsDictionary, any, UnfollowRequestParams>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const { user_id: follow_user_id } = req.params
  const result = await usersService.unfollow(user_id, follow_user_id)
  return res.json({
    result
  })
}

export const changePasswordController = async (
  req: Request<ParamsDictionary, any, ChangePasswordRequestBody>,
  res: Response
) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const { password } = req.body
  const result = await usersService.changePassword(user_id, password)
  return res.json({
    result
  })
}

export const oauthController = async (req: Request<ParamsDictionary, any, LoginReqBody>, res: Response) => {
  const { code } = req.query
  const result = await usersService.oauth(code as string)
  const urlRedirect = `${process.env.CLIENT_REDIRECT_CALLBACK_URL as string}?access_token=${
    result.access_token
  }&refresh_token=${result.refresh_token}&new_user=${result.newUser}`
  return res.redirect(urlRedirect)
}

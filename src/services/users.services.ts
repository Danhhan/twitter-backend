import axios from 'axios'

import { TokenType, UserVeriFyStatus } from '~/constants/enum'
import { LoginReqBody, RegisterReqBody, UpdateMeRequestBody } from '~/models/requests/User.requests'
import { User } from '~/models/schema/User.schema'
import { hashPassword } from '~/utils/crypto'
import { signToken } from '~/utils/jwt'
import databaseService from './database.services'
import httpStatus from '~/constants/httpStatus'
import { ErrorWithStatus } from '~/models/Error'
import RefreshToken from '~/models/schema/Refresh.schema'
import { ObjectId, WithId } from 'mongodb'
import { userMessages } from '~/constants/message'
import Follower from '~/models/schema/Followers.schema'

class UsersService {
  private signAccessToken({ user_id, verify }: { user_id: string; verify: UserVeriFyStatus }) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.AccessToken,
        verify
      },
      privateKey: process.env.JWT_SECRET_ACCESS_TOKEN as string,
      options: {
        expiresIn: process.env.EMAIL_VERIFY_TOKEN_EXPIRES_IN
      }
    })
  }

  private signRefreshToken({ user_id, verify }: { user_id: string; verify: UserVeriFyStatus }) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.RefreshToken,
        verify
      },
      privateKey: process.env.JWT_SECRET_REFRESH_TOKEN as string,
      options: {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN
      }
    })
  }

  private signEmailVerifyToken({ user_id, verify }: { user_id: string; verify: UserVeriFyStatus }) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.EmailVerifyToken,
        verify
      },
      privateKey: process.env.JWT_SECRET_EMAIL_VERIFY_TOKEN as string,
      options: {
        expiresIn: process.env.EMAIL_VERIFY_TOKEN_EXPIRES_IN
      }
    })
  }

  private signForgotPasswordToken({ user_id, verify }: { user_id: string; verify: UserVeriFyStatus }) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.EmailVerifyToken,
        verify
      },
      privateKey: process.env.JWT_SECRET_FORGOT_PASSWORD_TOKEN as string,
      options: {
        expiresIn: process.env.EMAIL_FORGOT_PASSWORD_EXPIRES_IN
      }
    })
  }

  private signAccessAndRefreshToken({ user_id, verify }: { user_id: string; verify: UserVeriFyStatus }) {
    return Promise.all([
      this.signAccessToken({
        user_id: user_id,
        verify
      }),
      this.signRefreshToken({
        user_id: user_id,
        verify
      })
    ])
  }

  private insertRefreshToken(user_id: string, refresh_token: string) {
    return databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token })
    )
  }

  async register(payload: RegisterReqBody) {
    const user_id = new ObjectId()
    const email_verify_token = await this.signEmailVerifyToken({
      user_id: user_id.toString(),
      verify: UserVeriFyStatus.Unverified
    })
    const result = await databaseService.users.insertOne(
      new User({
        ...payload,
        _id: user_id,
        email_verify_token,
        date_of_birth: new Date(payload.date_of_birth),
        password: hashPassword(payload.password)
      })
    )
    const [access_token, refresh_token] = await this.signAccessAndRefreshToken({
      user_id: user_id.toString(),
      verify: UserVeriFyStatus.Unverified
    })
    await this.insertRefreshToken(user_id.toString(), refresh_token)
    return {
      access_token,
      refresh_token
    }
  }

  async checkEmailExist(email: string) {
    const user = await databaseService.users.findOne({ email })
    return Boolean(user)
  }

  async login(payload: LoginReqBody) {
    const user = await databaseService.users.findOne({ email: payload.email, password: hashPassword(payload.password) })
    if (!user) {
      throw new ErrorWithStatus({ status: httpStatus.NOT_FOUND, message: userMessages.EMAIL_OR_PASSWORD_IS_INCORRECT })
    }
    const { _id, verify } = user
    const user_id = _id.toString()
    const [access_token, refresh_token] = await this.signAccessAndRefreshToken({
      user_id,
      verify
    })
    await this.insertRefreshToken(user_id, refresh_token)
    return {
      access_token,
      refresh_token
    }
  }

  async logout(refresh_token: string) {
    await databaseService.refreshTokens.deleteOne({ token: refresh_token })
    return {
      message: userMessages.LOGOUT_SUCCESS
    }
  }
  async verifyEmail(user_id: string) {
    const [token] = await Promise.all([
      this.signAccessAndRefreshToken({ user_id, verify: UserVeriFyStatus.Verified }),
      databaseService.users.updateOne(
        { _id: new ObjectId(user_id) },
        {
          $set: {
            verify: UserVeriFyStatus.Verified,
            email_verify_token: ''
            // updated_at: new Date()
          },
          $currentDate: {
            updated_at: true
          }
        }
      )
    ])
    const [access_token, refresh_token] = token
    await this.insertRefreshToken(user_id, refresh_token)
    return {
      access_token,
      refresh_token
    }
  }
  async resendVerifyEmail(user_id: string) {
    const email_verify_token = await this.signEmailVerifyToken({ user_id, verify: UserVeriFyStatus.Unverified })
    await databaseService.users.updateOne(
      { _id: new ObjectId(user_id) },
      {
        $set: {
          email_verify_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
  }
  async forgotPassword({ user_id, verify }: { user_id: string; verify: UserVeriFyStatus }) {
    const forgot_password_token = await this.signForgotPasswordToken({ user_id, verify })
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: {
          forgot_password_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    // send email will go here
    console.log('forgot_password_token: ', forgot_password_token)
  }
  async resetPassword(user_id: string, password: string) {
    databaseService.users.updateOne(
      { _id: new ObjectId(user_id) },
      {
        $set: {
          password: hashPassword(password),
          forgot_password_token: ''
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return true
  }
  async getMe(user_id: string) {
    const user = await databaseService.users.findOne(
      { _id: new ObjectId(user_id) },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0
        }
      }
    )
    return user
  }

  async getProfile(username: string) {
    const user = await databaseService.users.findOne(
      { username },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0
        }
      }
    )
    return user
  }

  async updateMe(user_id: string, payload: UpdateMeRequestBody) {
    const _payload = payload.date_of_birth ? { ...payload, date_of_birth: new Date(payload.date_of_birth) } : payload
    console.log('_payload: ', _payload)

    const user = await databaseService.users.findOneAndUpdate(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: {
          ...(_payload as UpdateMeRequestBody & { date_of_birth?: Date })
        },
        $currentDate: {
          updated_at: true
        }
      },
      {
        returnDocument: 'after',
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0
        }
      }
    )
    return user as WithId<User>
  }
  async follow(user_id: string, follow_user_id: string) {
    const follower = await databaseService.followers.findOne({
      user_id: new ObjectId(user_id),
      follow_user_id: new ObjectId(follow_user_id)
    })
    if (follower === null) {
      await databaseService.followers.insertOne(
        new Follower({ user_id: new ObjectId(user_id), follow_user_id: new ObjectId(follow_user_id) })
      )
      return {
        message: userMessages.FOLLOW_SUCCESS
      }
    }
    return {
      message: userMessages.ALREADY_FOLLOW_THIS_USER
    }
  }

  async unfollow(user_id: string, follow_user_id: string) {
    const follower = await databaseService.followers.findOne({
      user_id: new ObjectId(user_id),
      follow_user_id: new ObjectId(follow_user_id)
    })
    if (follower === null) {
      await databaseService.followers.insertOne(
        new Follower({ user_id: new ObjectId(user_id), follow_user_id: new ObjectId(follow_user_id) })
      )
      return {
        message: userMessages.ALREADY_UNFOLLOW_THIS_USER
      }
    }
    await databaseService.followers.deleteOne({
      user_id: new ObjectId(user_id),
      follow_user_id: new ObjectId(follow_user_id)
    })
    return {
      message: userMessages.UNFOLLOW_SUCCESS
    }
  }
  async changePassword(user_id: string, password: string) {
    const user = await databaseService.users.findOneAndUpdate(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: {
          password: hashPassword(password)
        },
        $currentDate: {
          updated_at: true
        }
      },
      {
        returnDocument: 'after',
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0
        }
      }
    )
    return user
  }
  private async getOAuthGoogleToken(code: string) {
    const body = {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_AUTHORIZED_REDIRECT_URL,
      grant_type: 'authorization_code'
    }
    const { data } = await axios.post('https://oauth2.googleapis.com/token', body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    return data as {
      access_token: string
      id_token: string
    }
  }

  private async getGoogleUserInfo(access_token: string, id_token: string) {
    const { data } = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
      params: {
        access_token,
        alt: 'json',
        headers: {
          Authorization: `Bearer ${id_token}`
        }
      }
    })
    return data as {
      id: string
      email: string
      verified_email: boolean
      name: string
      given_name: string
      family_name: string
      picture: string
      locale: string
    }
  }

  async oauth(code: string) {
    const { id_token, access_token } = await this.getOAuthGoogleToken(code)
    const userInfo = await this.getGoogleUserInfo(access_token, id_token)
    console.log('userInfo: ', userInfo)
    if (!userInfo.verified_email) {
      throw new ErrorWithStatus({ status: httpStatus.BAD_REQUEST, message: userMessages.GMAIL_NOT_VERIFIED })
    }
    const user = await databaseService.users.findOne({ email: userInfo.email })
    const user_id = user?._id.toString() as string
    if (user) {
      const [access_token, refresh_token] = await this.signAccessAndRefreshToken({
        user_id,
        verify: user.verify
      })
      await this.insertRefreshToken(user_id, refresh_token)
      return {
        access_token,
        refresh_token,
        newUser: false
      }
    } else {
      const password = Math.random().toString(36).slice(-8)
      const data = await this.register({
        email: userInfo.email,
        name: userInfo.name,
        password,
        date_of_birth: new Date(),
        avatar: userInfo.picture,
        confirm_password: password
      })
      return { ...data, newUser: true }
    }
  }
}
const usersService = new UsersService()
export default usersService

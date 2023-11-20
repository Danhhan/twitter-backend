import { NextFunction, Request, Response } from 'express'
import { ParamSchema, checkSchema } from 'express-validator'
import { JsonWebTokenError } from 'jsonwebtoken'
import { ObjectId } from 'mongodb'
import { UserVeriFyStatus } from '~/constants/enum'
import httpStatus from '~/constants/httpStatus'
import { userMessages } from '~/constants/message'
import { REGEX_USERNAME } from '~/constants/regex'
import { ErrorWithStatus } from '~/models/Error'
import { TokenPayload } from '~/models/requests/User.requests'
import databaseService from '~/services/database.services'
import usersService from '~/services/users.services'
import { hashPassword } from '~/utils/crypto'
import { verifyToken } from '~/utils/jwt'
import { validate } from '~/utils/validation'

const passwordSchema: ParamSchema = {
  notEmpty: {
    errorMessage: userMessages.PASSWORD_IS_REQUIRED
  },
  isLength: {
    options: {
      min: 6,
      max: 100
    },
    errorMessage: userMessages.PASSWORD_LENGTH_MUST_BE_FROM_6_TO_100
  },
  isStrongPassword: {
    options: {
      minLength: 6,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSymbols: 1
    },
    errorMessage: userMessages.PASSWORD_MUST_BE_STRONG
  }
}

const confirmPasswordSchema: ParamSchema = {
  notEmpty: {
    errorMessage: userMessages.CONFIRM_PASSWORD_IS_REQUIRED
  },
  isLength: {
    options: {
      min: 6,
      max: 100
    },
    errorMessage: userMessages.PASSWORD_LENGTH_MUST_BE_FROM_6_TO_100
  },
  isStrongPassword: {
    options: {
      minLength: 6,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSymbols: 1
    },
    errorMessage: userMessages.PASSWORD_MUST_BE_STRONG
  },
  custom: {
    options: (value, { req }) => {
      if (value !== req.body.password) {
        throw Error(userMessages.PASSWORDS_DO_NOT_MATCH)
      }
      return true
    }
  }
}

const nameSchema: ParamSchema = {
  notEmpty: {
    errorMessage: userMessages.NAME_IS_REQUIRED
  },
  isString: {
    errorMessage: userMessages.NAME_MUST_BE_A_STRING
  },
  trim: true,
  isLength: {
    options: {
      min: 1,
      max: 100
    },
    errorMessage: userMessages.NAME_LENGTH_MUST_BE_FROM_1_TO_100
  }
}

const dateOfBirthSchema: ParamSchema = {
  isISO8601: {
    options: {
      strict: true,
      strictSeparator: true
    },
    errorMessage: userMessages.DATE_OF_BIRTH_MUST_BE_IS8601
  }
}

const imageSchema: ParamSchema = {
  optional: true,
  isString: {
    errorMessage: userMessages.IMAGE_MUST_BE_A_STRING
  },
  trim: true,
  isLength: {
    options: {
      min: 1,
      max: 400
    },
    errorMessage: userMessages.IMAGE_LENGTH_MUST_BE_FROM_1_TO_400
  }
}

const userIdSchema: ParamSchema = {
  custom: {
    options: async (value: string, { req }) => {
      if (!ObjectId.isValid(value)) {
        throw new ErrorWithStatus({
          message: userMessages.USER_ID_IS_INVALID,
          status: httpStatus.NOT_FOUND
        })
      }
      const follow_user = await databaseService.users.findOne({ _id: new ObjectId(value) })
      if (follow_user === null) {
        throw new ErrorWithStatus({
          message: userMessages.USER_NOT_FOUND,
          status: httpStatus.NOT_FOUND
        })
      }
    }
  }
}

const forgotPasswordTokenSchema: ParamSchema = {
  trim: true,
  custom: {
    options: async (value: string, { req }) => {
      if (!value) {
        throw new ErrorWithStatus({
          status: httpStatus.UNAUTHORIZED,
          message: userMessages.FORGOT_PASSWORD_TOKEN_IS_REQUIRED
        })
      }
      try {
        const decoded_forgot_password_token = await verifyToken({
          token: value,
          secretOrPublicKey: process.env.JWT_SECRET_FORGOT_PASSWORD_TOKEN as string
        })
        const { user_id } = decoded_forgot_password_token
        const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
        if (user === null) {
          throw new ErrorWithStatus({
            status: httpStatus.NOT_FOUND,
            message: userMessages.USER_NOT_FOUND
          })
        }
        if (user.forgot_password_token !== value) {
          throw new ErrorWithStatus({
            status: httpStatus.NOT_FOUND,
            message: userMessages.INVALID_FORGOT_PASSWORD_TOKEN
          })
        }
        req.decoded_forgot_password_token = decoded_forgot_password_token
      } catch (error) {
        if (error instanceof JsonWebTokenError) {
          throw new ErrorWithStatus({
            status: httpStatus.UNAUTHORIZED,
            message: error.message
          })
        }
        throw error
      }
    }
  }
}

export const loginValidator = validate(
  checkSchema(
    {
      email: {
        isEmail: {
          errorMessage: userMessages.EMAIL_IS_INVALID
        },
        trim: true
      },
      password: {
        notEmpty: {
          errorMessage: userMessages.PASSWORD_IS_REQUIRED
        },
        isLength: {
          options: {
            min: 6,
            max: 100
          },
          errorMessage: userMessages.PASSWORD_LENGTH_MUST_BE_FROM_6_TO_100
        },
        isStrongPassword: {
          options: {
            minLength: 6,
            minUppercase: 1,
            minLowercase: 1,
            minNumbers: 1,
            minSymbols: 1
          },
          errorMessage: userMessages.PASSWORD_MUST_BE_STRONG
        }
      }
    },
    ['body']
  )
)

export const registerValidator = validate(
  checkSchema(
    {
      name: nameSchema,
      email: {
        notEmpty: {
          errorMessage: userMessages.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: userMessages.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value) => {
            const isExistEmail = await usersService.checkEmailExist(value)
            if (isExistEmail) {
              throw new ErrorWithStatus({
                status: httpStatus.CONFLICT,
                message: userMessages.EMAIL_ALREADY_EXISTS
              })
            }
            return isExistEmail
          }
        }
      },
      password: passwordSchema,
      confirm_password: confirmPasswordSchema,
      date_of_birth: dateOfBirthSchema
    },
    ['body']
  )
)

export const accessTokenValidator = validate(
  checkSchema(
    {
      Authorization: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            const accessToken = (value || '').split(' ')[1]
            if (!accessToken) {
              throw new ErrorWithStatus({
                status: httpStatus.UNAUTHORIZED,
                message: userMessages.AUTHORIZATION_HEADER_IS_REQUIRED
              })
            }
            try {
              const decoded_authorization = await verifyToken({
                token: accessToken,
                secretOrPublicKey: process.env.JWT_SECRET_ACCESS_TOKEN as string
              })
              /** SHOULD REFACTOR */
              // const { user_id } = decoded_authorization
              // const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
              // if (user === null) {
              //   throw new ErrorWithStatus({
              //     status: httpStatus.NOT_FOUND,
              //     message: userMessages.USER_NOT_FOUND
              //   })
              // }
              ;(req as Request).decoded_authorization = decoded_authorization
            } catch (error) {
              throw new ErrorWithStatus({
                status: httpStatus.UNAUTHORIZED,
                message: (error as JsonWebTokenError).message
              })
            }
            return true
          }
        }
      }
    },
    ['headers']
  )
)

export const refreshTokenValidator = validate(
  checkSchema(
    {
      refresh_token: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            if (!value) {
              throw new ErrorWithStatus({
                status: httpStatus.UNAUTHORIZED,
                message: userMessages.REFRESH_TOKEN_IS_REQUIRED
              })
            }
            try {
              const [decoded_refresh_token, refresh_token] = await Promise.all([
                verifyToken({ token: value, secretOrPublicKey: process.env.JWT_SECRET_REFRESH_TOKEN as string }),
                databaseService.refreshTokens.findOne({ token: value })
              ])
              if (refresh_token === null) {
                throw new ErrorWithStatus({
                  status: httpStatus.UNAUTHORIZED,
                  message: userMessages.USED_REFRESH_TOKEN_OR_REFRESH_TOKEN_NOT_EXIST
                })
              }
              ;(req as Request).decoded_refresh_token = decoded_refresh_token
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  status: httpStatus.UNAUTHORIZED,
                  message: error.message
                })
              }
              throw error
            }
          }
        }
      }
    },
    ['body']
  )
)

export const emailVerifyTokenValidator = validate(
  checkSchema(
    {
      email_verify_token: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            if (!value) {
              throw new ErrorWithStatus({
                status: httpStatus.UNAUTHORIZED,
                message: userMessages.EMAIL_VERIFICATION_TOKEN_IS_REQUIRED
              })
            }
            try {
              const decoded_email_verify_token = await verifyToken({
                token: value,
                secretOrPublicKey: process.env.JWT_SECRET_EMAIL_VERIFY_TOKEN as string
              })
              ;(req as Request).decoded_email_verify_token = decoded_email_verify_token
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  status: httpStatus.UNAUTHORIZED,
                  message: error.message
                })
              }
              throw error
            }
          }
        }
      }
    },
    ['body']
  )
)

export const forgotPasswordValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: {
          errorMessage: userMessages.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: userMessages.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            const user = await databaseService.users.findOne({ email: value })
            if (user === null) {
              throw new ErrorWithStatus({
                status: httpStatus.NOT_FOUND,
                message: userMessages.USER_NOT_FOUND
              })
            }
            req.user = user
            return true
          }
        }
      }
    },
    ['body']
  )
)

export const verifyForgotPasswordTokenValidator = validate(
  checkSchema(
    {
      forgot_password_token: forgotPasswordTokenSchema
    },
    ['body']
  )
)

export const resetPasswordValidator = validate(
  checkSchema({
    forgot_password_token: forgotPasswordTokenSchema,
    password: passwordSchema,
    confirm_password: confirmPasswordSchema
  })
)

export const verifiedUserValidator = (req: Request, res: Response, next: NextFunction) => {
  const { verify } = req.decoded_authorization as TokenPayload
  if (verify !== UserVeriFyStatus.Unverified) {
    return next(
      new ErrorWithStatus({
        message: userMessages.USER_NOT_VERIFIED,
        status: httpStatus.FORBIDDEN
      })
    )
  }
  next()
  return null
}

export const updateMeValidator = validate(
  checkSchema(
    {
      name: {
        optional: true,
        ...nameSchema,
        notEmpty: undefined
      },
      date_of_birth: {
        ...dateOfBirthSchema,
        optional: true
      },
      bio: {
        optional: true,
        isString: {
          errorMessage: userMessages.BIO_MUST_BE_A_STRING
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: userMessages.BIO_LENGTH_MUST_BE_FROM_1_TO_200
        }
      },
      location: {
        optional: true,
        isString: {
          errorMessage: userMessages.LOCATION_MUST_BE_A_STRING
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: userMessages.LOCATION_LENGTH_MUST_BE_FROM_1_TO_200
        }
      },
      website: {
        optional: true,
        isString: {
          errorMessage: userMessages.LOCATION_MUST_BE_A_STRING
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: userMessages.LOCATION_LENGTH_MUST_BE_FROM_1_TO_200
        }
      },
      username: {
        optional: true,
        isString: {
          errorMessage: userMessages.USERNAME_MUST_BE_A_STRING
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            if (!REGEX_USERNAME.test(value)) {
              throw new ErrorWithStatus({
                status: httpStatus.UNPROCESSABLE_ENTITY,
                message: userMessages.USERNAME_INVALID
              })
            }
            const user = await databaseService.users.findOne({ username: value })
            if (user) {
              throw new ErrorWithStatus({
                status: httpStatus.CONFLICT,
                message: userMessages.USERNAME_ALREADY_EXISTS
              })
            }
          }
        }
      },
      avatar: imageSchema,
      cover_photo: imageSchema
    },
    ['body']
  )
)

export const followValidator = validate(
  checkSchema(
    {
      follow_user_id: userIdSchema
    },
    ['body']
  )
)

export const unfollowValidator = validate(
  checkSchema(
    {
      user_id: userIdSchema
    },
    ['params']
  )
)

export const changePasswordValidator = validate(
  checkSchema({
    old_password: {
      ...passwordSchema,
      custom: {
        options: async (value, { req }) => {
          const { user_id } = req.decoded_authorization as TokenPayload
          const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
          if (!user) {
            throw new ErrorWithStatus({
              status: httpStatus.NOT_FOUND,
              message: userMessages.USER_NOT_FOUND
            })
          }
          const { password } = user
          const isMatched = hashPassword(value) === password
          if (!isMatched) {
            throw new ErrorWithStatus({
              status: httpStatus.UNAUTHORIZED,
              message: userMessages.OLD_PASSWORD_NOT_MATCHED
            })
          }
        }
      }
    },
    password: passwordSchema,
    confirm_password: confirmPasswordSchema
  })
)

import { config } from 'dotenv'
import jwt, { SignOptions } from 'jsonwebtoken'
import { generatePrivateKey } from './crypto'
import { TokenPayload } from '~/models/requests/User.requests'

config()
export interface ParamsJwt {
  payload: string | Buffer | object
  privateKey: string
  options?: SignOptions
}
export const signToken = async ({
  payload,
  privateKey,
  options = {
    algorithm: 'RS256'
  }
}: ParamsJwt) => {
  // eslint-disable-next-line no-useless-catch
  try {
    const result = await jwt.sign(payload, privateKey, options)
    return result
  } catch (error) {
    throw error
  }
}
export const verifyToken = async ({
  token,
  secretOrPublicKey = process.env.JWT_SECRET as string
}: {
  token: string
  secretOrPublicKey?: string
}) => {
  return new Promise<TokenPayload>((resolve, reject) => {
    jwt.verify(token, secretOrPublicKey, (error, decoded) => {
      if (error) {
        reject(error)
      }
      resolve(decoded as TokenPayload)
    })
  })
}

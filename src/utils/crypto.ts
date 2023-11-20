import { createHash, createPrivateKey } from 'crypto'

export function sha256(content: string) {
  return createHash('sha256').update(content).digest('hex')
}

export function hashPassword(password: string) {
  return sha256(password + process.env.PASSWORD_SECRET)
}
export const generatePrivateKey = () => createPrivateKey(process.env.JWT_SECRET as string)

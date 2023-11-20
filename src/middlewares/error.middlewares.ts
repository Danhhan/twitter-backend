import { Request, Response, NextFunction } from 'express'
import { omit } from 'lodash'
import httpStatus from '~/constants/httpStatus'
import { ErrorWithStatus } from '~/models/Error'

export const defaultErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof ErrorWithStatus) {
    return res.status(err.status || httpStatus.INTERNAL_SERVER_ERROR).json(omit(err, 'status'))
  }
  Object.getOwnPropertyNames(err).forEach((key) => {
    Object.defineProperty(err, key, { enumerable: true })
  })
  const errorInfo = process.env.NODE_ENV === 'production' ? omit(err, 'stack') : err
  return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
    message: err.message,
    errorInfo
  })
}

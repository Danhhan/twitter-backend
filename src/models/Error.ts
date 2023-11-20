import httpStatus from '~/constants/httpStatus'
import { userMessages } from '~/constants/message'

type ErrorType = Record<
  string,
  {
    msg: string
    [key: string]: any
  }
>
export class ErrorWithStatus {
  message: string
  status: number
  constructor({ message, status }: { message: string; status: number }) {
    this.message = message
    this.status = status
  }
}
export class EntityError extends ErrorWithStatus {
  errors: ErrorType
  constructor({
    message = userMessages.VALIDATION_ERROR,
    status = httpStatus.UNPROCESSABLE_ENTITY,
    errors = {}
  }: {
    message?: string
    status?: number
    errors?: ErrorType
  }) {
    super({ message, status })
    this.errors = errors
  }
}

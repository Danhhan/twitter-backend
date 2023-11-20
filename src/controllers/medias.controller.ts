import { NextFunction, Response, Request } from 'express'
import formidable from 'formidable'

export const uploadSingleImageController = async (req: Request, res: Response, next: NextFunction) => {
  const form = formidable({ multiples: true })
  return res.json({
    message: 'Upload single image success'
  })
}

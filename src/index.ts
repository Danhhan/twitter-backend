import express from 'express'
import usersRouter from '~/routes/users.routes'
import databaseService from '~/services/database.services'
import { defaultErrorHandler } from './middlewares/error.middlewares'
import mediasRouter from './routes/media.routes'
const app = express()
const port = 4000

app.use(express.json())
app.use('/users', usersRouter)
app.use('/medias', mediasRouter)
/**
This is the handle error
If you don't add param like this, nodejs will understand like handle request
*/
app.use(defaultErrorHandler)
databaseService.connect()
app.listen(port, () => {
  console.log(`app listening on port ${port}`)
})

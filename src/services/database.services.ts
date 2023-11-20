import { Collection, Db, MongoClient, ClientSession } from 'mongodb'
import { config } from 'dotenv'
import { User } from '~/models/schema/User.schema'
import RefreshToken from '~/models/schema/Refresh.schema'
import Follower from '~/models/schema/Followers.schema'
config()
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.2hfoqzv.mongodb.net/?retryWrites=true&w=majority`

class DatabaseService {
  private client: MongoClient
  private db: Db
  constructor() {
    this.client = new MongoClient(uri)
    this.db = this.client.db(process.env.DB_NAME)
  }
  async connect() {
    try {
      // Send a ping to confirm a successful connection
      await this.db.command({ ping: 1 })
      console.log('Pinged your deployment. You successfully connected to MongoDB!')
    } catch (error) {
      console.log(error)
      this.client.close()
    }
  }
  get users(): Collection<User> {
    return this.db.collection('users')
  }
  get refreshTokens(): Collection<RefreshToken> {
    return this.db.collection(process.env.REFRESH_TOKENS_COLLECTION as string)
  }
  get followers(): Collection<Follower> {
    return this.db.collection(process.env.FOLLOWERS_COLLECTION as string)
  }
}
const databaseService = new DatabaseService()
export default databaseService

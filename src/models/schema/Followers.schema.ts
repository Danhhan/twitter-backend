import { ObjectId } from 'mongodb'

interface FollowerType {
  _id?: ObjectId
  created_at?: Date
  user_id: ObjectId
  follow_user_id: ObjectId
}
export default class Follower {
  _id?: ObjectId
  created_at?: Date
  user_id: ObjectId
  follow_user_id: ObjectId

  constructor({ _id, follow_user_id, created_at, user_id }: FollowerType) {
    this._id = _id
    this.follow_user_id = follow_user_id
    this.created_at = created_at || new Date()
    this.user_id = user_id
  }
}

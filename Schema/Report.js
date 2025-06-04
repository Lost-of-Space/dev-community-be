import mongoose, { Schema } from "mongoose";

const reportSchema = mongoose.Schema({
  from: {
    type: Schema.Types.ObjectId,
    ref: 'users',
    required: true
  },
  post_id: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: 'posts'
  },
  text: {
    type: String,
    required: true,
    maxlength: 500
  },
  status: {
    type: String,
    enum: ['pending', 'reviewed', 'rejected'],
    default: 'pending'
  }
}, {
  timestamps: {
    createdAt: 'createdAt'
  }
});

export default mongoose.model("reports", reportSchema);

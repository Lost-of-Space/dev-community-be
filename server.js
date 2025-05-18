import express from 'express';
import mongoose from 'mongoose';//for db connection
import 'dotenv/config'
import bcrypt from 'bcryptjs'; //for hashing
import { nanoid } from 'nanoid';//id generator
import jwt from 'jsonwebtoken';
import { config } from "./config.js";
import admin from "firebase-admin";
import serviceAccountKey from "./dev-community-7f3b8-firebase-adminsdk-lzctm-9acd813bc6.json" with {type: "json"}
import { getAuth } from "firebase-admin/auth"

//schema
import User from './Schema/User.js';
import Post from './Schema/Post.js';
import Notification from './Schema/Notification.js';
import Comment from './Schema/Comment.js';

import cors from 'cors';

const server = express();
let PORT = 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey)
})

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());

// Only enable CORS if it's development environment
if (config.IS_DEV_ENV) {
  server.use(cors({ origin: 'http://localhost:5173', credentials: true }));
}

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true
})


const verifyJWT = (req, res, next) => {
  const authHeader = req.headers['x-authorization'];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res.status(401).json({ error: "No access token." })
  }

  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access token is invalid." })
    }

    req.user = user.id
    req.admin = user.admin
    req.blocked = user.blocked
    next()
  })
}

const formatDataToSend = (user) => {

  const access_token = jwt.sign({ id: user._id, admin: user.admin, blocked: user.blocked }, process.env.SECRET_ACCESS_KEY)

  return {
    access_token,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
    email: user.personal_info.email,
    profile_img: user.personal_info.profile_img,
    isAdmin: user.admin,
    isBlocked: user.blocked
  }
}

const generateUsername = async (email) => {
  let username = email.split("@")[0];
  let isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then((result) => result)
  //add unique string to username
  isUsernameNotUnique ? username += nanoid().substring(0, 5) : "";

  return username
}


server.post("/signup", (req, res) => {

  let { fullname, email, password } = req.body;

  //Data validation
  if (fullname.length < 4) {
    return res.status(403).json({ "error": "Fullname must be at least 4 letters long." })
  }
  if (!email.length) {
    return res.status(403).json({ "error": "Enter email." })
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ "error": "Email is invalid." })
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({ "error": "Password should be 6 to 20 chars long with a numeric, lower case and upper case." })
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    //generates username from email
    let username = await generateUsername(email);

    let user = new User({
      personal_info: { fullname, email, password: hashed_password, username }
    })

    user.save().then((u) => {

      return res.status(200).json(formatDataToSend(u))

    })
      .catch(err => {

        if (err.code == 11000) {
          return res.status(500).json({ "error": "Email is already in use." })
        }

        return res.status(500).json({ "error": err.message })
      })

  })

})

server.post("/signin", (req, res) => {

  let { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ "error": "Invalid Credentials." }) //Email not found
      }

      if (!user.provider_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res.status(403).json({ "error": "Error occured while login please try again" })
          }
          if (!result) {
            return res.status(403).json({ "error": "Invalid Credentials." }) //Incorrect password
          } else {
            return res.status(200).json(formatDataToSend(user))
          }

        });

      } else {
        return res.status(403).json({ "error": "Account was created using Google. Please, use Google to log in." })
      }

    })

    .catch(err => {
      console.log(err.message);
      return res.status(500).json({ "error": err.message })
    })
})


//Google auth
server.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;

  try {
    const decodedUser = await getAuth().verifyIdToken(access_token);
    const { email, name } = decodedUser;

    const existingUser = await User.findOne({ "personal_info.email": email });

    if (existingUser) {
      if (!existingUser.provider_auth) {
        return res.status(403).json({
          error: "This email is already used without Google. login with password or Github."
        });
      }

      return res.status(200).json(formatDataToSend(existingUser));
    }

    const username = await generateUsername(email);

    const newUser = new User({
      personal_info: { fullname: name, email, username },
      provider_auth: true
    });

    const savedUser = await newUser.save();
    return res.status(200).json(formatDataToSend(savedUser));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to authenticate with Google." });
  }
});


//Github auth
server.post("/github-auth", async (req, res) => {
  let { access_token } = req.body;

  try {
    const decodedUser = await getAuth().verifyIdToken(access_token);
    const { email, name } = decodedUser;

    const existingUser = await User.findOne({ "personal_info.email": email });

    if (existingUser) {
      if (!existingUser.provider_auth) {
        return res.status(403).json({
          error: "This email is already used without Github. login with password or Google."
        });
      }

      return res.status(200).json(formatDataToSend(existingUser));
    }

    const username = await generateUsername(email);

    const newUser = new User({
      personal_info: { fullname: name, email, username },
      provider_auth: true
    });

    const savedUser = await newUser.save();
    return res.status(200).json(formatDataToSend(savedUser));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to authenticate with Github." });
  }
});


/*
  Posts
*/

// Latest Posts
server.post('/latest-posts', (req, res) => {

  let { page } = req.body;

  let maxLimit = 10; // The limit of posts that comes from server

  Post.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("post_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(posts => {
      return res.status(200).json({ posts })
    })
    .catch(err => {
      return res.status(500).json({ error: err.message })
    })
})

server.post("/all-latest-posts-count", (req, res) => {
  Post.countDocuments({ draft: false })
    .then(count => {
      return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
      console.log(err.message);
      return res.status(500).json({ error: err.message })
    })
})

server.get("/top-tags", async (req, res) => {
  try {
    const topTags = await Post.aggregate([
      { $match: { draft: false } },
      { $unwind: "$tags" },
      { $group: { _id: "$tags", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    res.status(200).json({ tags: topTags.map(tag => tag._id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Popular Posts
server.get("/popular-posts", (req, res) => {
  Post.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "activity.total_read": -1, "activity.total_likes": -1, "publishedAt": -1 })
    .select("post_id title publishedAt -_id")
    .limit(10)
    .then(posts => {
      return res.status(200).json({ posts })
    })
    .catch(err => {
      return res.status(500).json({ error: err.message })
    })
})

//Get Posts
server.post("/get-post", (req, res) => {
  let { post_id, draft, mode } = req.body;

  let incrementVal = mode != 'edit' ? 1 : 0;

  Post.findOneAndUpdate({ post_id }, { $inc: { "activity.total_reads": incrementVal } })
    .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt post_id tags")
    .then(post => {

      User.findOneAndUpdate({ "personal_info.username": post.author.personal_info.username }, {
        $inc: { "account_info.total_reads": incrementVal }
      })
        .catch(err => {
          return res.status(500).json({ error: err.message });
        })

      if (post.draft && !draft) {
        return res.status(500).json({ error: 'You can not access a draft post' })
      }
      return res.status(200).json({ post });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    })

})

// Searching
server.post("/search-posts", (req, res) => {
  let { tag, query, author, page, limit, eliminate_post } = req.body;

  let maxLimit = limit ? limit : 5;

  let findQuery = { draft: false };

  if (tag) {
    if (Array.isArray(tag)) {
      findQuery.tags = { $in: tag.map(t => new RegExp(`^${t}$`, 'i')) };
    } else if (typeof tag === "string") {
      findQuery.tags = new RegExp(`^${tag}$`, 'i');
    }
  } else if (query) {
    findQuery.$or = [
      { title: new RegExp(query, 'i') },
      { des: new RegExp(query, 'i') }
    ];
  } else if (author) {
    findQuery.author = author;
  }

  if (eliminate_post) {
    findQuery.post_id = { $ne: eliminate_post };
  }

  Post.find(findQuery)
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("post_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(posts => {
      return res.status(200).json({ posts });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/search-posts-count", (req, res) => {
  let { tag, query, author } = req.body;

  let findQuery = { draft: false };

  if (tag) {
    if (Array.isArray(tag)) {
      findQuery.tags = { $in: tag.map(t => new RegExp(`^${t}$`, 'i')) };
    } else if (typeof tag === "string") {
      findQuery.tags = new RegExp(`^${tag}$`, 'i');
    }
  } else if (query) {
    findQuery.$or = [
      { title: new RegExp(query, 'i') },
      { des: new RegExp(query, 'i') }
    ];
  } else if (author) {
    findQuery.author = author;
  }

  Post.countDocuments(findQuery)
    .then(count => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/search-users", (req, res) => {
  let { query, isExact } = req.body;

  let searchCondition;

  if (isExact) {
    //searching by @username
    searchCondition = { "personal_info.username": new RegExp(`^${query}`, 'i') };
  } else {
    //default search
    searchCondition = {
      $or: [
        { "personal_info.username": new RegExp(query, 'i') },
        { "personal_info.fullname": new RegExp(query, 'i') }
      ]
    };
  }

  User.find(searchCondition)
    .limit(50)
    .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then(users => {
      return res.status(200).json({ users });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });
});

//Get user profile
server.post("/get-profile", (req, res) => {

  let { username } = req.body;

  User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -provider_auth -updatedAt -posts")
    .then(user => {
      return res.status(200).json(user);
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });
})



// Create Post
server.post('/create-post', verifyJWT, (req, res) => {

  let authorId = req.user;

  let { title, des, banner, tags, content, draft, id } = req.body;

  if (!title.length) {
    return res.status(403).json({ error: "You must provide a title." });
  }

  if (!draft) {
    if (!des.length || des.length > 200) {
      return res.status(403).json({ error: "You must provide a description under 200 characters." });
    }

    if (!banner.length) {
      return res.status(403).json({ error: "You must provide a banner." });
    }

    if (!content.blocks.length) {
      return res.status(403).json({ error: "There must be some content." });
    }

    if (!tags.length || tags.length > 10) {
      return res.status(403).json({ error: "There must be at least one tag, maximum 10." });
    }
  }

  tags = tags.map(tag => tag.toLowerCase());

  let post_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + "-" + nanoid();

  if (id) {
    Post.findOneAndUpdate({ post_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
      .then(() => {
        return res.status(200).json({ id: post_id })
      })
      .catch(err => {
        return res.status(500).json({ error: err.message })
      })
  }

  else {
    let post = new Post({
      title, des, banner, content, tags, author: authorId, post_id, draft: Boolean(draft)
    })

    post.save().then(post => {

      // test if post draft == true or false, and updating total posts count
      let incrementVal = draft ? 0 : 1;
      User.findOneAndUpdate({ _id: authorId }, { $inc: { "account_info.total_posts": incrementVal }, $push: { "posts": post._id } })

        .then(user => {
          return res.status(200).json({ id: post.post_id })
        })

        .catch(err => {
          return res.status(500).json({ error: "Failed tp update total posts number" })
        })
    })
      .catch(err => {
        return res.status(500).json({ error: err.message })
      })
  }
})

server.post("/like-post", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { _id, isLikedByUser } = req.body;

  let incrementVal = !isLikedByUser ? 1 : -1;

  Post.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
    .then(post => {
      if (!isLikedByUser) {
        let like = new Notification({
          type: "like",
          post: _id,
          notification_for: post.author,
          user: user_id
        })

        like.save().then(notification => {
          return res.status(200).json({ liked_by_user: true })
        })
      } else {
        Notification.findOneAndDelete({ user: user_id, post: _id, type: "like" })
          .then(data => {
            return res.status(200).json({ liked_by_user: false })
          })

          .catch(err => {
            return res.status(500).json({ error: err.message })
          })
      }
    })
})

server.post("/isliked-by-user", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { _id } = req.body;

  Notification.exists({ user: user_id, type: "like", post: _id })
    .then(result => {
      return res.status(200).json({ result })
    })
    .catch(err => {
      return res.status(500).json({ error: err.message })
    })
})

server.post("/add-comment", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { _id, comment, post_author, replying_to, notification_id } = req.body;

  if (!comment.length) {
    return res.status(403).json({ error: 'Comment cannot be empty.' });
  }

  let commentObj = {
    post_id: _id, post_author, comment, commented_by: user_id
  }

  if (replying_to) {
    commentObj.parent = replying_to;
    commentObj.isReply = true;
  }

  new Comment(commentObj).save().then(async commentFile => {
    let { comment, commentedAt, children } = commentFile;

    Post.findOneAndUpdate({ _id }, { $push: { "comments": commentFile._id }, $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 }, })
      .then(post => { console.log('comment added.') })

    let notificationObj = {
      type: replying_to ? "reply" : "comment",
      post: _id,
      notification_for: post_author,
      user: user_id,
      comment: commentFile._id
    }

    if (replying_to) {
      notificationObj.replied_on_comment = replying_to;

      await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
        .then(replyingToCommentDoc => { notificationObj.notification_for = replyingToCommentDoc.commented_by })

      if (notification_id) {
        Notification.findOneAndUpdate({ _id: notification_id }, { reply: commentFile._id })
          .then(notification => { console.log('notification updated.') })
      }
    }

    new Notification(notificationObj).save().then(notification => console.log('notification created.'))

    return res.status(200).json({
      comment, commentedAt, _id: commentFile._id, user_id, children
    })

  })

})

server.post("/get-post-comments", (req, res) => {
  let { post_id, skip } = req.body;

  let maxLimit = 5;

  Comment.find({ post_id, isReply: false })
    .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({
      'commentedAt': -1
    })
    .then(comment => {
      return res.status(200).json(comment)
    })
    .catch(err => {
      return res.status(500).json({ error: err.message })
    })
})

server.post("/get-replies", (req, res) => {
  let { _id, skip } = req.body;

  let maxLimit = 5;
  Comment.findOne({ _id })
    .populate({
      path: "children",
      options: {
        limit: maxLimit,
        skip: skip,
        sort: { 'commentedAt': -1 }
      },
      populate: {
        path: 'commented_by',
        select: "personal_info.profile_img personal_info.fullname personal_info.username"
      },
      select: "-post_id -updatedAt"
    })
    .select("children")
    .then(doc => {
      return res.status(200).json({ replies: doc.children })
    })
    .catch(err => {
      return res.status(500).json({ error: err.message })
    })
})


const deleteComments = (_id) => {
  Comment.findOneAndDelete({ _id })
    .then(comment => {
      if (comment.parent) {
        Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
          .then(data => console.log('comment delete from parent'))
          .catch(err => console.log(err));
      }

      Notification.findOneAndDelete({ comment: _id }).then(notification => console.log('comment notification removed.'))
      Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } }).then(notification => console.log('reply notification removed.'))

      Post.findOneAndUpdate({ _id: comment.post_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1 }, "activity.total_parent_comments": comment.parent ? 0 : -1 })
        .then(post => {
          if (comment.children.length) {
            comment.children.map(replies => {
              deleteComments(replies)
            })
          }
        })
        .catch(err => {
          console.log(err.message);
        })
    })
}

server.post("/delete-comment", verifyJWT, (req, res) => {
  let user_id = req.user;
  let { _id } = req.body;

  Comment.findOne({ _id })
    .then(comment => {
      if (user_id == comment.commented_by || user_id == comment.post_author) {
        deleteComments(_id);

        return res.status(200).json({ status: 'done' })

      } else {
        return res.status(403).json({ error: "Do not have permission." })
      }
    })
})

/*

  Account settings

*/
server.post("/change-password", verifyJWT, (req, res) => {
  let { currentPassword, newPassword } = req.body;

  if (!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)) {
    return res.status(403).json({ error: "Password should be 6 to 20 chars long with at least 1 numeric, 1 lowercase and 1 uppercase letters." })
  }

  User.findOne({ _id: req.user })
    .then((user) => {
      if (user.provider_auth) {
        return res.status(403).json({ error: "Password cannot be changed if you're using a provider auth method." })
      }

      bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
        if (err) {
          return res.status(500).json({ error: "Error occured while changing password, please try again later." })
        }

        if (!result) {
          return res.status(500).json({ error: "Password didn't match." })
        }

        bcrypt.hash(newPassword, 10, (err, hashed_password) => {
          User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashed_password })
            .then((u) => {
              return res.status(200).json({ status: "Password changed." })
            })
            .catch(err => {
              return res.status(500).json({ error: "Error occured while saving new password, please try again later." })
            })
        })
      })
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({ error: "User not found." })
    })
})

server.post("/update-profile-img", verifyJWT, (req, res) => {
  let { url } = req.body;

  User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
    .then(() => {
      return res.status(200).json({ profile_img: url })
    })
    .catch(err => {
      return res.status(500).json({ error: err.message })
    })
})

server.post("/update-profile", verifyJWT, (req, res) => {
  let { username, bio, social_links } = req.body;

  let bioLimit = 150;

  if (username.length < 3) {
    return res.status(403).json({ error: "Username should be at least 3 chars long." })
  }

  if (bio.length > bioLimit) {
    return res.status(403).json({ error: `Bio should not be more than ${bioLimit} chars.` })
  }

  let socialLinksArr = Object.keys(social_links);

  try {

    for (let i = 0; i < socialLinksArr.length; i++) {
      if (social_links[socialLinksArr[i]].length) {
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

        if (!hostname.includes(`${socialLinksArr[i]}.com`) && socialLinksArr[i] != 'website') {
          return res.status(403).json({ error: `${socialLinksArr[i]} link is invalid. You must enter a valid URL`, });
        }
      }
    }

  } catch (err) {
    return res.status(500).json({ error: "You must provide full social links with http(s) included" });
  }

  let updateObj = {
    "personal_info.username": username,
    "personal_info.bio": bio,
    social_links
  }

  User.findOneAndUpdate({ _id: req.user }, updateObj, {
    runValidators: true
  })
    .then(() => {
      return res.status(200).json({ username })
    })
    .catch(err => {
      if (err.code == 11000) {
        return res.status(409).json({ error: "Username is already taken." })
      }
      return res.status(500).json({ error: err.message })
    })

})

/*

  Notifications

*/

server.get("/new-notification", verifyJWT, (req, res) => {
  let user_id = req.user;
  Notification.exists({ notification_for: user_id, seen: false, user: { $ne: user_id } })
    .then(result => {
      if (result) {
        return res.status(200).json({ new_notification_available: true })
      } else {
        return res.status(200).json({ new_notification_available: false })
      }
    })
    .catch(err => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    })
})

server.post("/notifications", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { page, filter, deletedDocCount } = req.body;

  let maxLimit = 5;

  let findQuery = { notification_for: user_id, user: { $ne: user_id } };

  let skipDocs = (page - 1) * maxLimit;

  if (filter != 'all') {
    findQuery.type = filter;
  }

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate('post', 'post_id title')
    .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
    .populate("comment", "comment")
    .populate("replied_on_comment", "comment")
    .populate("reply", "comment")
    .sort({ createdAt: -1 })
    .select("createdAt type seen reply")
    .then(notifications => {

      Notification.updateMany(findQuery, { seen: true })
        .skip(skipDocs)
        .limit(maxLimit)
        .then(() => { console.log("notification seen") })

      return res.status(200).json({ notifications });
    })
    .catch(err => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    })
})

server.post("/all-notifications-count", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { filter } = req.body;

  let findQuery = { notification_for: user_id, user: { $ne: user_id } }

  if (filter != 'all') {
    findQuery.type = filter;
  }

  Notification.countDocuments(findQuery)
    .then(count => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    })

})

/*

  Dashboard

*/

server.post("/user-written-posts", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { page, draft, query, deletedDocCount } = req.body;

  let maxLimit = 5;
  let skipDocs = (page - 1) * maxLimit;

  if (deletedDocCount) {
    skipDocs -= deletedDocCount
  }

  Post.find({ author: user_id, draft, title: new RegExp(query, 'i') })
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({ publishedAt: -1 })
    .select(" title banner publishedAt post_id activity des draft -_id")
    .then(posts => {
      return res.status(200).json({ posts })
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    })

})

server.post("/user-written-posts-count", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { draft, query } = req.body;

  Post.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
    .then(count => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    })
})

server.post("/delete-post", verifyJWT, (req, res) => {
  let user_id = req.user;
  let { post_id } = req.body;

  Post.findOneAndDelete({ post_id })
    .then(post => {
      Notification.deleteMany({ post: post._id })
        .then(data => console.log('notifications deleted'))
      Comment.deleteMany({ post_id: post._id })
        .then(data => console.log('comments deleted'))
      User.findOneAndUpdate({ _id: user_id }, { $pull: { posts: post._id }, $inc: { "account_info.total_posts": post.draft ? 0 : -1 } })
        .then(user => console.log('post deleted'))
      return res.status(200).json({ status: 'done' });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    })
})

server.post("/get-user-statistics", verifyJWT, async (req, res) => {
  const { days } = req.body;
  const user_id = req.user;

  const now = new Date();
  const fromDate = new Date(now);
  fromDate.setDate(now.getDate() - days);

  try {
    const recentPosts = await Post.find({
      author: user_id,
      publishedAt: { $gte: fromDate, $lte: now }
    }).select("publishedAt");

    const allPosts = await Post.find({ author: user_id });

    const totalStats = {
      total_posts: allPosts.length,
      total_comments: allPosts.reduce((sum, post) => sum + (post.activity?.total_comments || 0), 0),
      total_likes: allPosts.reduce((sum, post) => sum + (post.activity?.total_likes || 0), 0),
      total_reads: allPosts.reduce((sum, post) => sum + (post.activity?.total_reads || 0), 0)
    };

    const commentDates = await Comment.find({
      post_id: { $in: allPosts.map(post => post._id) },
      commentedAt: { $gte: fromDate, $lte: now }
    }).select("commentedAt");

    return res.status(200).json({ recentPosts, totalStats, commentDates });

  } catch (err) {
    console.error("Error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});



/*

  Control Panel

*/

server.post("/get-users", verifyJWT, async (req, res) => {
  let {
    page, filter, query, userFilter = {}, deletedDocCount,
    isAdmin, sortField, sortOrder
  } = req.body;

  const maxLimit = 6;
  let skipDocs = (page - 1) * maxLimit;

  if (!isAdmin) {
    return res.status(403).json({ error: "Access denied." });
  }

  let findQuery = {};

  if (filter !== "all" && query) {
    findQuery["$or"] = [
      { "personal_info.username": { $regex: query, $options: "i" } },
      { "personal_info.fullname": { $regex: query, $options: "i" } }
    ];
  }

  let roleFilters = [];
  if (userFilter.admin) roleFilters.push({ admin: true });
  if (userFilter.user) roleFilters.push({ admin: false });
  if (userFilter.blocked) roleFilters.push({ blocked: true });

  if (roleFilters.length > 0) {
    findQuery["$and"] = roleFilters;
  }

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  try {
    const users = await User.find(findQuery)
      .skip(skipDocs)
      .limit(maxLimit)
      .select("personal_info.fullname personal_info.username personal_info.profile_img personal_info.email admin blocked account_info joinedAt")
      .sort({ [sortField]: sortOrder === "asc" ? 1 : -1 });

    return res.status(200).json({ users });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.post("/get-users-count", verifyJWT, async (req, res) => {
  let { filter, query, userFilter = {} } = req.body;

  let findQuery = {};

  if (filter !== "all" && query) {
    findQuery["$or"] = [
      { "personal_info.username": { $regex: query, $options: "i" } },
      { "personal_info.fullname": { $regex: query, $options: "i" } }
    ];
  }

  let roleFilters = [];
  if (userFilter.admin) roleFilters.push({ admin: true });
  if (userFilter.user) roleFilters.push({ admin: false });
  if (userFilter.blocked) roleFilters.push({ blocked: true });

  if (roleFilters.length > 0) {
    findQuery["$and"] = roleFilters;
  }

  try {
    const count = await User.countDocuments(findQuery);
    return res.status(200).json({ totalDocs: count });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: err.message });
  }
});

server.patch("/toggle-user-flag", async (req, res) => {
  const { targetUserId, isAdmin, field } = req.body;

  if (!isAdmin) {
    return res.status(403).json({ error: "Access denied. Only admins can change user flags." });
  }

  if (!["admin", "blocked"].includes(field)) {
    return res.status(400).json({ error: "Invalid field provided." });
  }

  try {
    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    targetUser[field] = !targetUser[field];
    await targetUser.save();

    return res.status(200).json({
      message: `User '${field}' status changed successfully.`,
      [field]: targetUser[field],
    });

  } catch (error) {
    console.error("Error toggling user flag:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.post("/get-user-stats", verifyJWT, async (req, res) => {
  const { days, isAdmin } = req.body;

  if (!isAdmin) {
    return res.status(403).json({ error: "Access denied" });
  }

  try {
    const now = new Date();
    const fromDate = new Date(now);
    fromDate.setDate(now.getDate() - days);

    const recentUsers = await User.find(
      { joinedAt: { $gte: fromDate, $lte: now } },
      "joinedAt"
    )
      .lean();

    const totalUsers = await User.countDocuments();
    const blockedUsers = await User.countDocuments({ blocked: true });

    res.json({
      recentUsers,
      totalUsers,
      blockedUsers,
    });
  } catch (err) {
    console.error("Error fetching user stats:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

server.post("/get-post-stats", verifyJWT, async (req, res) => {
  const { days, isAdmin } = req.body;

  if (!isAdmin) {
    return res.status(403).json({ error: "Access denied" });
  }

  try {
    const now = new Date();
    const fromDate = new Date(now);
    fromDate.setDate(now.getDate() - days);

    const recentPosts = await Post.find(
      { publishedAt: { $gte: fromDate, $lte: now } },
      "publishedAt"
    ).lean();

    const totalPosts = await Post.countDocuments();
    const totalDrafts = await Post.countDocuments({ draft: true });

    res.json({
      recentPosts,
      totalPosts,
      totalDrafts,
    });
  } catch (err) {
    console.error("Error fetching post stats:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

server.post("/get-posts-adm", verifyJWT, async (req, res) => {
  let {
    page, filter, query, postFilter = {}, deletedDocCount,
    isAdmin, sortField, sortOrder
  } = req.body;

  const maxLimit = 6;
  let skipDocs = (page - 1) * maxLimit;

  if (!isAdmin) {
    return res.status(403).json({ error: "Access denied." });
  }

  let findQuery = {};

  if (filter !== "all" && query) {
    if (query.startsWith("@")) {
      const username = query.slice(1);
      const users = await User.find({
        "personal_info.username": { $regex: username, $options: "i" }
      }).select("_id");

      const userIds = users.map(user => user._id);

      if (userIds.length) {
        findQuery["author"] = { $in: userIds };
      } else {
        return res.status(200).json({ posts: [] });
      }
    } else {
      findQuery["title"] = { $regex: query, $options: "i" };
    }
  }

  let statusFilters = [];
  if (postFilter.published) statusFilters.push({ draft: false });
  if (postFilter.draft) statusFilters.push({ draft: true });

  if (statusFilters.length > 0) {
    findQuery["$or"] = statusFilters;
  }

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  try {
    const posts = await Post.find(findQuery)
      .skip(skipDocs)
      .limit(maxLimit)
      .populate("author", "personal_info.fullname personal_info.username")
      .select("post_id title author activity.total_likes publishedAt draft")
      .sort({ [sortField]: sortOrder === "asc" ? 1 : -1 });

    const transformedPosts = posts.map(post => ({
      ...post.toObject(),
      author: {
        username: post.author.personal_info.username
      }
    }));

    return res.status(200).json({ posts: transformedPosts });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.post("/get-posts-count-adm", verifyJWT, async (req, res) => {
  let { filter, query, postFilter = {} } = req.body;

  let findQuery = {};

  if (filter !== "all" && query) {
    if (query.startsWith("@")) {
      const username = query.slice(1);
      const users = await User.find({
        "personal_info.username": { $regex: username, $options: "i" }
      }).select("_id");

      const userIds = users.map(user => user._id);

      if (userIds.length) {
        findQuery["author"] = { $in: userIds };
      } else {
        return res.status(200).json({ totalDocs: 0 });
      }
    } else {
      findQuery["title"] = { $regex: query, $options: "i" };
    }
  }

  let statusFilters = [];
  if (postFilter.published) statusFilters.push({ draft: false });
  if (postFilter.draft) statusFilters.push({ draft: true });

  if (statusFilters.length > 0) {
    findQuery["$or"] = statusFilters;
  }

  try {
    const count = await Post.countDocuments(findQuery);
    return res.status(200).json({ totalDocs: count });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: err.message });
  }
});


server.listen(PORT, () => {
  console.log('Listening on port: ' + PORT);
});
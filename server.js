import express from "express";
import mongoose from "mongoose";
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from "nanoid";
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from "firebase-admin";
import { getAuth } from 'firebase-admin/auth';
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { createRequire } from 'module';
import OpenAI from "openai";

const require = createRequire(import.meta.url);
const serviceAccountkey = require('./crixblog-55694-firebase-adminsdk-fbsvc-346ca2bad8.json');

import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";
import { populate } from "dotenv";
import { title } from "process";
import { totalmem } from "os";

const app = express();
const PORT = 3001;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountkey)
});


let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

//middleware
app.use(express.json());
app.use(cors())

// database connection
mongoose.connect(process.env.DB_LOCATION, { dbName: 'blogweb' })
    .then(() => console.log("DataBase is connected."))
    .catch((err) => console.log("Database connection failed", err))

// Setting s3 bucket 
// const s3 = new aws.S3({
//     region: 'eu-north-1',
//     accessKeyId: process.env.AWS_ACCESS_KEY,
//     secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
// })

// aws 
const s3 = new S3Client({
    region: 'eu-north-1',
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    }
});


// const generateUploadURL = async () => {

//     const date = new Date();
//     const imageName = `${nanoid()}-${date.getTime()}.jpeg`;

//     return await s3.getSignedUrlPromise('putObject', {
//         Bucket: 'crixblog',
//         Key: imageName,
//         Expires: 1000,
//         ContentType: "image/jpeg"
//     })
// }


const openai = new OpenAI({
    apiKey: process.env.OPENROUTER_API_KEY,
    baseURL: "https://openrouter.ai/api/v1",  // ✅ required for OpenRouter keys
});
  
const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`;

    const command = new PutObjectCommand({
        Bucket: 'crixblog',
        Key: imageName,
        ContentType: 'image/jpeg',
    });

    const signedUrl = await getSignedUrl(s3, command, { expiresIn: 1000 });
    return signedUrl;
};

const verifyJWT = (req, res, next) => {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (token == null) {
        return res.status(401).json({ error: "No access token." });
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Access token is Invalid." });
        }

        req.user = user.id;
        next();
    })
}


const formatDatatoSend = (user) => {

    const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY)

    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname
    }
}

const generateUsername = async (email) => {
    let username = email.split("@")[0];

    const isUserNameNotUnique = await User.exists({ "personal_info.username": username }).then((result) => result)

    isUserNameNotUnique ? username += nanoid().substring(0, 5) : '';
    return username
}

// upload image URL
app.get('/get-upload-url', (req, res) => {
    generateUploadURL()
        .then(url => res.status(200).json({ uploadURL: url }))
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        })
})

// signup page
app.post("/signup", (req, res) => {

    const { fullname, email, password } = req.body;

    // validating data from frontend
    if (fullname.length < 3) {
        return res.status(403).json({ error: "Fullname must be at least 3 letters long" });
    }

    if (!email.length) {
        return res.status(403).json({ "error": "Enter the email" })
    }

    if (!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Email is invalid" })
    }

    if (!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters " })
    }

    bcrypt.hash(password, 10, async (err, hashPassword) => {
        let username = await generateUsername(email);

        const user = new User({
            personal_info: { fullname, email, password: hashPassword, username }
        })

        user.save()
            .then((data) => {
                return res.status(200).json(formatDatatoSend(data))
            })
            .catch(err => {

                //email exists or not
                if (err.code === 11000) {
                    return res.status(500).json({ "error": "Email already exists" })
                }
                return res.status(500).json({ "error": err.message })
            })
    })

});

// signIn page
app.post('/signin', (req, res) => {

    const { email, password } = req.body;

    User.findOne({ "personal_info.email": email })
        .then((user) => {
            if (!user) {
                return res.status(403).json({ "error": 'Email not found' })
            }

            if (!user.google_auth) {
                bcrypt.compare(password, user.personal_info.password, (err, result) => {
                    if (err) {
                        return res.status(403).json({ "error": "Error occured while login please try again." });
                    }

                    if (!result) {
                        return res.status(403).json({ "error": "Incorrect Password" })
                    } else {
                        return res.status(200).json(formatDatatoSend(user))
                    }
                })
            }
            else {
                return res.status(403).json({ "error": "Account was created using google. Try logging in with" })
            }
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ "error": err.message })
        })
})

// change password
app.post('/change-password', verifyJWT, (req, res) => {
    let { currentPassword, newPassword } = req.body;

    if (!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)) {
        return res.status(403).json({ error: "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters" });
    }

    User.findOne({ _id: req.user })
        .then((user) => {
            if (user.google_auth) {
                return res.status(403).json({ error: "You can't change account password because you logged in through google" })
            }

            bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Some error occured while changing the password, try again later" })
                }
                if (!result) {
                    return res.status(403).json({ error: "Incorrect current password" })
                }
                bcrypt.hash(newPassword, 10, (err, hashed_password) => {
                    User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashed_password })
                        .then((us) => {
                            return res.status(200).json({ success: "Password Changed" })
                        })
                        .catch(err => {
                            return res.status(500).json({ success: "Some error occured while saving new password, try again later" })
                        })
                })
            })
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ error: "User not found" })
        })

})

// signup and signIn with google authentication
app.post('/google-auth', async (req, res) => {

    let { access_token } = req.body;

    getAuth()
        .verifyIdToken(access_token)
        .then(async (decodedUser) => {
            let { email, name, picture } = decodedUser;

            picture = picture.replace("s96-c", "s384-c")

            let user = await User.findOne({ "personal_info.email": email }).select("personal_info.fullname personal_info.username personal_info.profile_img google_auth")
                .then((u) => {
                    return u || null;
                })
                .catch(err => {
                    return res.status(500).json({ "error": err.message })
                })

            if (user) { //login
                if (!user.google_auth) {
                    return res.status(403).json({ "error": "This email was signed up without google .please log in with password to access the account." })
                }
            }
            else { //signup
                let username = await generateUsername(email);

                user = new User({
                    personal_info: { fullname: name, email, profile_img: picture, username },
                    google_auth: true
                })

                await user.save().then((u) => {
                    user = u;
                })
                    .catch(err => {
                        return res.status(500).json({ "error": err.message });
                    })
            }
            return res.status(200).json(formatDatatoSend(user))
        })
        .catch(err => {
            return res.status(500).json({ "error": "Failed to authenticate with google.Try with some other google account." })
        })
})

// Latest blogs 
app.post('/latest-blogs', (req, res) => {

    let { page } = req.body;

    const maxLimit = 5;

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

//all latests blog count
app.post('/all-latest-blogs-count', (req, res) => {
    Blog.countDocuments({ draft: false })
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })
})

// search blog count
app.post('/search-blogs-count', (req, res) => {

    let { tag, query, author } = req.body;
    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false };
    }
    else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    }
    else if (author) {
        findQuery = { author, draft: false }
    }

    Blog.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })
})

// search user by name
app.post('/search-users', (req, res) => {

    let { query } = req.body;

    User.find({ "personal_info.username": new RegExp(query, 'i') })
        .limit(50)
        .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
        .then(users => {
            return res.status(200).json({ users })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// when click user name redirect profile 
app.post('/get-profile', (req, res) => {

    const { username } = req.body;

    User.findOne({ "personal_info.username": username })
        .select("-personal_info.password -google_auth -updatedAt -blogs")
        .then(user => {
            return res.status(200).json(user)
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ error: err.message })
        })
})

// update profile image in edit profile page
app.post('/update-profile-img', verifyJWT, (req, res) => {
    let { url } = req.body;
    User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
        .then(() => {
            return res.status(200).json({ profile_img: url })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// update user all details in edit profile page
app.post('/update-profile', verifyJWT, (req, res) => {
    let { username, bio, social_links } = req.body;
    let bioLimit = 300;

    if (username.length < 3) {
        return res.status(403).json({ error: "Username shoud be at least 3 letters long." });
    }
    if (bio.length > bioLimit) {
        return res.status(403).json({ error: `Bio should not be more than ${bioLimit} letters.` });
    }

    let socialLinksArr = Object.keys(social_links);
    try {
        for (let i = 0; i < socialLinksArr.length; i++) {
            if (social_links[socialLinksArr[i]].length) {
                let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

                if (!hostname.includes(`${socialLinksArr[i]}.com`) &&
                    !(socialLinksArr[i] === "twitter" && hostname.includes("x.com")) &&
                    socialLinksArr[i] != "website") {
                    return res.status(403).json({ error: `${socialLinksArr[i]} links is invalid. You must enter a full link` })
                }

            }
        }
    }
    catch (err) {
        return res.status(500).json({ error: "You must provide full socail links with http(s) included." });
    }

    let updateObj = {
        "personal_info.username": username,
        "personal_info.bio": bio,
        social_links,
    }

    User.findOneAndUpdate({ _id: req.user }, updateObj, {
        runValidtors: true
    })
        .then(() => {
            return res.status(200).json({ username });
        })
        .catch(err => {
            if (err.code == 1100) {
                return res.status(404).json({ error: "Username is already taken, choose another username" });
            }
            return res.status(500).json({ error: err.message })
        })
})

// trending blogs
app.get('/trending-blogs', (req, res) => {
    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "activity.total_read": -1, "activity_likes": -1, "publishedAt": -1 })
        .select("blog_id title publishedAt -_id")
        .limit(5)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// create blogs 
app.post('/create-blog', verifyJWT, (req, res) => {

    let authorId = req.user;

    let { title, des, banner, tags, content, draft, id } = req.body;

    if (!title.length) {
        return res.status(403).json({ error: "You must providez a title." });
    }

    if (!draft) {
        if (!des.length || des.length > 200) {
            return res.status(403).json({ error: "You must write the blog description under 200 chaacters." });
        }

        if (!banner.length) {
            return res.status(403).json({ error: "You must provide a blog banner to publish it." });
        }

        if (!tags.length || tags.length > 10) {
            return res.status(403).json({ error: "Provides tags in order to publish to blog , Maximum 10." });
        }

        if (!content.blocks.length) {
            return res.status(403).json({ error: "You must provide some blog content to publish it." });
        }
    }

    tags = tags.map(tag => tag.toLowerCase());

    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();

    if (id) {

        Blog.findOneAndUpdate({ blog_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
            .then(() => {
                return res.status(200).json({ id: blog_id })
            })
            .catch(err => {
                return res.status(500).json({ error: "Failed to update total posts number" })
            })
    }
    else {
        let blog = new Blog({
            title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
        })

        blog.save()
            .then(blog => {

                let incrementVal = draft ? 0 : 1;

                User.findOneAndUpdate({ _id: authorId }, { $inc: { "account_info.total_posts": incrementVal }, $push: { "blogs": blog._id } })
                    .then(user => {
                        return res.status(200).json({ id: blog.blog_id })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: "Failed to update total posts number." })
                    })
            })
            .catch(err => {
                return res.status(500).json({ error: err.message })
            })
    }
})

// searching any blogs
app.post('/search-blogs', (req, res) => {
    const { tag, page, query, author, limit, eliminate_blog } = req.body;
    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } };
    }
    else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    }
    else if (author) {
        findQuery = { author, draft: false }
    }

    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

})

// when user click any blog redirect this route and open this blog
app.post('/get-blog', (req, res) => {

    const { blog_id, draft, mode } = req.body;

    const incrementVal = mode != 'edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": incrementVal } })
        .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
        .select("title des content banner activity publishedAt blog_id tags")
        .then(blog => {
            User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, {
                $inc: { "account_info.total_reads": incrementVal }
            })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })

            if (blog.draft && !draft) {
                return res.status(500).json({ error: 'You can not access draft blogs' })
            }

            return res.status(200).json({ blog })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// liked blogs
app.post('/like-blog', verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id, isLikedByUser } = req.body;

    let incrementVal = !isLikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
        .then(blog => {

            if (!isLikedByUser) {
                let like = new Notification({
                    type: "like",
                    blog: _id,
                    notification_for: blog.author,
                    user: user_id,
                })

                like.save()
                    .then(notification => {
                        return res.status(200).json({ liked_by_user: true });
                    })
            }
            else {

                Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" })
                    .then(data => {
                        return res.status(200).json({ liked_by_user: false })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message })
                    })

            }
        })

})

// like information
app.post('/isLiked-by-user', verifyJWT, (req, res) => {

    let user_id = req.user;
    let { _id } = req.body;

    Notification.exists({ user: user_id, type: "like", blog: _id })
        .then(result => {
            return res.status(200).json({ result })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

})

// write comment
app.post('/add-comment', verifyJWT, (req, res) => {
    const user_id = req.user;

    let { _id, comment, blog_author, replying_to, notification_id } = req.body;

    if (!comment.length) {
        return res.status(403).json({ error: 'Write something to leave a comment' });
    }

    const commentObj = {
        blog_id: _id,
        blog_author,
        comment,
        commented_by: user_id
    }

    if (replying_to) {
        commentObj.parent = replying_to;
        commentObj.isReply = true;
    }

    new Comment(commentObj).save()
        .then(async commentFile => {
            const { comment, commentedAt, children } = commentFile;

            Blog.findOneAndUpdate(
                { _id },
                {
                    $push: { comments: commentFile._id },
                    $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 }
                }
            )
                .then(() => console.log('New comment added to blog'));

            const notificationObj = {
                type: replying_to ? "reply" : "comment",
                blog: _id,
                notification_for: blog_author,
                user: user_id,
                comment: commentFile._id
            }

            if (replying_to) {
                notificationObj.replied_on_comment = replying_to;

                await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
                    .then(replyingToCommentDoc => { notificationObj.notification_for = replyingToCommentDoc.commented_by })

                if (notification_id) {
                    Notification.findOneAndUpdate({ _id: notification_id }, { reply: commentFile._id })
                        .then(notification => {
                            console.log('notification updated')
                        })
                }
            }

            new Notification(notificationObj).save()
                .then(() => console.log('New notification created'));

            return res.status(200).json({
                comment,
                commentedAt,
                _id: commentFile._id,
                user_id,
                children
            });
        })
        .catch(err => {
            console.error('Error saving comment:', err);
            return res.status(500).json({ error: 'Failed to save comment' });
        });
});

// replies of the comment
app.post('/get-replies', (req, res) => {
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
                select: 'personal_info.profile_img personal_info.fullname personal_info.username'
            },
            select: "-blog_id -updatedAt"
        })
        .select("children")
        .then(doc => {
            return res.status(200).json({ replies: doc.children });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        })
})

// delete comments

// const deleteCommets = (_id) => {
//     Comment.findOneAndDelete({ _id })
//         .then(comment => {
//             if (comment.parent) {
//                 Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
//                     .then(data => console.log("Comment Delete From Parent."))
//                     .catch(err => console.log(err));
//             }

//             Notification.findOneAndDelete({ comment: _id })
//                 .then(notification => console.log('comment notification deleted'))

//             Notification.findOneAnd({ reply: _id })
//                 .then(notification => console.log("Reply notification deleted."))

//             Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1 }, "activity.total_parent_comments": comment.parent ? 0 : -1 })
//                 .then(blog => {
//                     if (comment.children.length) {
//                         comment.children.map(replies => {
//                             deleteCommets(replies);
//                         })
//                     }
//                 })
//         })
//         .catch(err => {
//             console.log(err.message)
//         })
// }
// ,
// app.post('/delete-comments', verifyJWT, (req, res) => {
//     let user_id = req.user;
//     let { _id } = req.body;
//     Comment.findOne({ _id })
//         .then(comment => {
//             if (user_id == comment.commented_by || user_id == comment.blog_author) {
//                 deleteCommets(_id);

//                 return res.status(200).json({ sucsess: "Done✅" })
//             }
//             else {
//                 return res.status(403).json({ error: "You can not delete this comment." })
//             }
//         })
// })

const deleteComments = async (_id) => {
    try {
        const comment = await Comment.findOneAndDelete({ _id });

        if (!comment) return; // Nothing to delete

        // If this is a reply, remove it from its parent
        if (comment.parent) {
            await Comment.findOneAndUpdate(
                { _id: comment.parent },
                { $pull: { children: _id } }
            );
            console.log("Comment removed from parent.");
        }

        // Delete related notifications
        await Notification.deleteMany({ $or: [{ comment: _id }, { reply: _id }] });
        console.log("Related notifications deleted.");

        // Update the blog's comment counts
        await Blog.findOneAndUpdate(
            { _id: comment.blog_id },
            {
                $pull: { comments: _id },
                $inc: {
                    "activity.total_comments": -1,
                    "activity.total_parent_comments": comment.parent ? 0 : -1
                }
            }
        );

        // Recursively delete all replies
        if (comment.children?.length) {
            for (let replyId of comment.children) {
                await deleteComments(replyId);
            }
        }

    } catch (err) {
        console.error("Error deleting comment:", err.message);
    }
};

app.post('/delete-comments', verifyJWT, async (req, res) => {
    try {
        const user_id = req.user;
        const { _id } = req.body;

        const comment = await Comment.findOne({ _id });

        if (!comment) {
            return res.status(404).json({ error: "Comment not found" });
        }

        // Check permissions
        if (String(user_id) !== String(comment.commented_by) &&
            String(user_id) !== String(comment.blog_author)) {
            return res.status(403).json({ error: "You cannot delete this comment." });
        }

        await deleteComments(_id);
        return res.status(200).json({ success: "Comment deleted ✅" });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// fetch comment
app.post('/get-blog-comments', (req, res) => {
    let { blog_id, skip } = req.body;

    let maxLimit = 5;
    Comment.find({ blog_id, isReply: false })
        .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
        .skip(skip)
        .limit(maxLimit)
        .sort({
            'commentedAt': -1
        })
        .then(comment => {
            return res.status(200).json(comment);
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })
})

// increase read
app.post('/increase-read', async (req, res) => {
    try {
        const { blog_id } = req.body;

        const blog = await Blog.findOneAndUpdate(
            { _id: blog_id },
            { $inc: { 'activity.total_reads': 1 } },
            { new: true }
        );

        if (blog) {
            await User.findOneAndUpdate(
                { _id: blog.author },
                { $inc: { 'account_info.total_reads': 1 } }
            );
        }

        res.status(200).json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

// Notification Alert 
app.get('/new-notification', verifyJWT, (req, res) => {
    let user_id = req.user;
    Notification.exists({ notification_for: user_id, seen: false, user: { $ne: user_id } })
        .then(result => {
            if (result) {
                return res.status(200).json({ new_notification_avail: true });
            }
            else {
                return res.status(200).json({ new_notificaton_avail: false });
            }
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        })
})

// notification page
app.post('/notification', verifyJWT, (req, res) => {
    let user_id = req.user;
    let { page, filter, deletedDocCount } = req.body;
    let maxLimit = 10;
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
        .populate('blog', 'title blog_id')
        .populate("user", 'personal_info.fullname personal_info.username personal_info.profile_img')
        .populate("comment", "comment")
        .populate("replied_on_comment", "comment")
        .populate("reply", "comment")
        .sort({ createdAt: -1 })
        .select("createdAt type seen reply")
        .then(notification => {
            Notification.updateMany(findQuery, { seen: true })
                .skip(skipDocs)
                .limit(maxLimit)
                .then(() => {
                    console.log('Notification seen');
                })
            return res.status(200).json({ notification });
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        })
})

// Notification count 
app.post('/all-notifications-count', verifyJWT, (req, res) => {
    let user_id = req.user;
    let { filter } = req.body;
    let findQuery = { notification_for: user_id, user: { $ne: user_id } }

    if (filter != 'all') {
        findQuery.type = filter;
    }

    Notification.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        })
})

// Blogs management-------------->
// written blogs
app.post('/user-written-blogs', verifyJWT, (req, res) => {
    let user_id = req.user;
    let { page, draft, query, deletedDocCount, } = req.body;
    let maxLimit = 5;
    let skipDocs = (page - 1) * maxLimit;

    if (deletedDocCount) {
        skipDocs -= deletedDocCount;
    }

    Blog.find({ author: user_id, draft, title: new RegExp(query, 'i') })
        .skip(skipDocs)
        .limit(maxLimit)
        .sort({ publishedAt: -1 })
        .select('title banner publishedAt blog_id activity des draft -_id')
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        })
})

// written blogs count
app.post('/user-written-blogs-count', verifyJWT, (req, res) => {

    let user_id = req.user;
    let { draft, query } = req.body;
    Blog.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
        .then(count => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        })
})

// blog delete
app.post('/delete-blog', verifyJWT, (req, res) => {

    let user_id = req.user;
    let { blog_id } = req.body;

    Blog.findOneAndDelete({ blog_id })
        .then(blog => {
            Notification.deleteMany({ blog: blog._id })
                .then(data => console.log('Notification Deleted.'));

            Comment.deleteMany({ blog_id: blog._id })
                .then(data => console.log('Comments Deleted.'));

            User.findOneAndUpdate({ _id: user_id }, { $pull: { blog: blog._id }, $inc: { 'account_info.total_posts': -1 } })
                .then(user => console.log('Blog Deleted.'));

            return res.status(200).json({ status: 'Done' });
        })
        .catch(err=>{
            return res.status(500).json({error:err.message});
        })
})

app.post("/generate-content", verifyJWT, async (req, res) => {
    try {
      const { title } = req.body;
  
      if (!title || !title.trim()) {
        return res.status(400).json({ error: "Title is required" });
      }
  
      // Call OpenAI
      const completion = await openai.chat.completions.create({
        model: "gpt-oss-20b", // lightweight + fast
        messages: [
          { role: "system", content: "You are a helpful blog writing assistant. Generate engaging blog content in plain text with markdown-style formatting. Use fenced code blocks (```language) for code snippets." },
          { role: "user", content: `Write a blog article about: "${title}" and include code examples if relevant.` }
        ],
      });
  
      const aiText = completion.choices[0].message.content;
  
      // ---- FORMAT TO EDITORJS ----
      const lines = aiText.split("\n");
      const blocks = [];
      let inCodeBlock = false;
      let codeBuffer = [];
      let codeLang = "";
  
      for (let line of lines) {
        line = line.trim();
  
        // detect code block start
        if (line.startsWith("```")) {
          if (!inCodeBlock) {
            inCodeBlock = true;
            codeLang = line.replace(/```/, "").trim() || "plaintext";
            codeBuffer = [];
          } else {
            // close code block
            inCodeBlock = false;
            blocks.push({
              type: "code",
              data: {
                code: codeBuffer.join("\n"),
                language: codeLang
              }
            });
            codeBuffer = [];
            codeLang = "";
          }
          continue;
        }
  
        if (inCodeBlock) {
          codeBuffer.push(line);
          continue;
        }
  
        // headers
        if (line.startsWith("# ")) {
          blocks.push({ type: "header", data: { text: line.replace("# ", ""), level: 2 } });
        } else if (line.startsWith("## ")) {
          blocks.push({ type: "header", data: { text: line.replace("## ", ""), level: 3 } });
        } 
        // unordered list
        else if (line.startsWith("- ")) {
          blocks.push({ type: "list", data: { style: "unordered", items: [line.replace("- ", "")] } });
        } 
        // ordered list
        else if (/^\d+\.\s/.test(line)) {
          blocks.push({ type: "list", data: { style: "ordered", items: [line.replace(/^\d+\.\s/, "")] } });
        } 
        // blockquote
        else if (line.startsWith("> ")) {
          blocks.push({ type: "quote", data: { text: line.replace("> ", ""), caption: "", alignment: "left" } });
        } 
        // normal paragraph
        else if (line !== "") {
          blocks.push({ type: "paragraph", data: { text: line } });
        }
      }
  
      const editorContent = {
        time: new Date().getTime(),
        blocks: [
          { type: "header", data: { text: title, level: 2 } },
          ...blocks
        ]
      };
  
      return res.status(200).json({ content: editorContent });
    } catch (error) {
      console.error("AI generation error:", error);
      return res.status(500).json({ error: "AI generation failed." });
    }
});
  

// listen port
app.listen(PORT, () => console.log(`Server at started -> ${PORT}`))
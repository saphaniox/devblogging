const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS configuration
const corsOptions = {
  origin: true,
  credentials: true,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log("MongoDB connected successfully"))
.catch(err => console.error("MongoDB connection error:", err));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

//memory storage
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);

// BlogPost Schema
const BlogPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subtitle: { type: String },
  content: { type: String, required: true },
  imageUrl: { type: String },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
}, { timestamps: true });

const BlogPost = mongoose.model("BlogPost", BlogPostSchema);

// function to upload image
const uploadToCloudinary = (buffer) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        resource_type: 'image',
        folder: 'blog-images',
        format: 'png',
        public_id: `blog-${Date.now()}-${Math.round(Math.random() * 1E9)}`,
      },
      (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result.secure_url);
        }
      }
    );
    uploadStream.end(buffer);
  });
};

// function to get token
const getTokenFromHeader = (req) => {
  const header = req.headers["authorization"] || req.headers["Authorization"];
  if (!header) return null;
  const parts = header.split(" ");
  if (parts.length !== 2) return null;
  return parts[1];
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = getTokenFromHeader(req);

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET || "fallback_secret", (err, payload) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = payload;
    next();
  });
};

// Auth routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign(
      { id: newUser._id, username: newUser.username },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "User created successfully",
      token,
      user: { id: newUser._id, username: newUser.username, email: newUser.email }
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Server error during signup" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "24h" }
    );

    res.json({ 
      message: "Login successful", 
      token, 
      user: { id: user._id, username: user.username, email: user.email } 
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.json({ message: "Logout successful" });
});

app.get("/api/auth/verify", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("username email _id");
    if (!user) return res.status(404).json({ message: "User not found" });
    
    res.json({ user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    console.error("Verify error:", error);
    res.status(500).json({ message: "Server error during token verification" });
  }
});

// Blog post routes
app.get("/api/posts", async (req, res) => {
  try {
    const posts = await BlogPost.find()
      .populate("author", "username")
      .sort({ createdAt: -1 });
    res.json(posts);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ message: "Server error fetching posts" });
  }
});

app.get("/api/posts/:id", async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id).populate("author", "username");
    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }
    res.json(post);
  } catch (error) {
    console.error("Error fetching post:", error);
    res.status(500).json({ message: "Server error fetching post" });
  }
});

app.post("/api/posts", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    const { title, subtitle, content } = req.body;
    let imageUrl = "";

    // Upload image
    if (req.file) {
      try {
        imageUrl = await uploadToCloudinary(req.file.buffer);
      } catch (uploadError) {
        console.error("Cloudinary upload error:", uploadError);
        return res.status(500).json({ message: "Failed to upload image" });
      }
    }

    const newPost = new BlogPost({
      title,
      subtitle,
      content,
      imageUrl,
      author: req.user.id,
    });

    await newPost.save();
    await newPost.populate("author", "username");
    
    res.status(201).json(newPost);
  } catch (error) {
    console.error("Error creating post:", error);
    res.status(500).json({ message: "Server error creating post" });
  }
});

app.put("/api/posts/:id", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    const { title, subtitle, content } = req.body;
    const post = await BlogPost.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    if (post.author.toString() !== req.user.id) {
      return res.status(403).json({ message: "Not authorized to edit this post" });
    }

    let imageUrl = post.imageUrl;
    
    // Upload new image if present
    if (req.file) {
      try {
        imageUrl = await uploadToCloudinary(req.file.buffer);
      } catch (uploadError) {
        console.error("Cloudinary upload error:", uploadError);
        return res.status(500).json({ message: "Failed to upload image" });
      }
    }

    const updatedPost = await BlogPost.findByIdAndUpdate(
      req.params.id,
      { title, subtitle, content, imageUrl },
      { new: true }
    ).populate("author", "username");

    res.json(updatedPost);
  } catch (error) {
    console.error("Error updating post:", error);
    res.status(500).json({ message: "Server error updating post" });
  }
});

app.delete("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    if (post.author.toString() !== req.user.id) {
      return res.status(403).json({ message: "Not authorized to delete this post" });
    }

    await BlogPost.findByIdAndDelete(req.params.id);
    res.json({ message: "Post deleted successfully" });
  } catch (error) {
    console.error("Error deleting post:", error);
    res.status(500).json({ message: "Server error deleting post" });
  }
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

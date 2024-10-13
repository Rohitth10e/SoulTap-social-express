
# 🌟 SoulTap - Social Media Platform 🌟
SoulTap is a modern social media platform built for connection and expression. Whether it’s sharing thoughts, liking posts, or uploading profile pictures, **SoulTap** makes it easy for users to engage and build communities.

## 🚀 Features
- **🔒 User Authentication**: Secure registration, login, and logout using JWT.
- **📝 Post Management**: Create, edit, and delete posts with ease.
- **💬 Like Functionality**: Like and unlike posts to show appreciation.
- **📸 Profile Picture Upload**: Personalize profiles by uploading photos.
- **🔔 Session Management**: Cookie-based JWT authentication for a seamless user experience.

## 🛠️ Technologies Used
- **Backend**: Node.js & Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT & bcrypt for secure password hashing
- **View Engine**: EJS for dynamic HTML templating
- **File Upload**: Multer for handling images
- **Other Libraries**: 
  - Moment.js for time formatting
  - Cookie-Parser for cookie handling

## ⚙️ Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Rohitth10e/SoulTap-social-express.git
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Environment Setup**:
   - Create a `.env` file with your MongoDB connection string and JWT secret.
   ```env
   MONGO_URI=your_mongo_connection_string
   JWT_SECRET=your_jwt_secret_key
   ```

4. **Run the server**:
   ```bash
   npm start
   ```

5. **Access the application**:
   Open your browser and navigate to [http://localhost:3000](http://localhost:3000).

## 🗂️ Folder Structure
```
SoulTap/
│
├── models/          # Mongoose schemas for User and Post
├── views/           # EJS templates for frontend rendering
├── public/          # Static files (CSS, JS, images)
├── config/          # Multer configuration for file uploads
└── server.js        # Main server file
```

## 🌐 Routes
- `/` - Home Page
- `/register` - User Registration
- `/login` - User Login
- `/profile` - View User Profile
- `/upload` - Upload Profile Picture
- `/post` - Create New Post
- `/like/:id` - Like/Unlike a Post
- `/edit/:id` - Edit a Post
- `/delete/:id` - Delete a Post
- `/logout` - User Logout

## 🛡️ Security Considerations
- **Passwords** are securely hashed using **bcrypt** before being stored.
- **JWT Tokens** are used for user authentication, and cookies are **httpOnly** to prevent XSS attacks.

## 📝 License
This project is licensed under the **MIT License**.

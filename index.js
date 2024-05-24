import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
const port = process.env.PORT;
const jwt_SECRET = process.env.JWT_SECRET ;

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
  app.use(express.static('public'));


// nodemailer transporter
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
        user: process.env.SMTP_USERNAME,
        pass: process.env.SMTP_PASSWORD
    }
});

// Function to send confirmation email
const sendConfirmationEmail = async (email) => {
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Confirmation Email',
            text: 'Thank you for signing up!'
               });
        console.log('Confirmation email sent');
    } catch (error) {
        console.error('Error sending confirmation email:', error);
    }
};

// Function to send login token email
const sendLoginTokenEmail = async (email, token) => {
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Login Token',
            text: 'Please use the following link to access your profile.',
            html: `<p>Please use the following link to access your profile: <a href="http://localhost:${port}/profile?token=${token}">Access Profile</a></p>`
        });
        console.log('Login token email sent');
    } catch (error) {
        console.error('Error sending login token email:', error);
    }
};

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/myDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('MongoDB is connected');
}).catch((error) => {
    console.error('Error connecting to MongoDB:', error);
});

// Define user schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isEmailConfirmed: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Generate JWT token
const generateJWTToken = (user) => {
    return jwt.sign({ id: user._id }, jwt_SECRET, { expiresIn: '1h' });
};

// Routes
app.get('/', (req, res) => {
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send('User already exists with this email.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });

        // Save the user to the database
        await newUser.save();

        // Send confirmation email
        await sendConfirmationEmail(email);

        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.send('An error occurred while signing up. Please try again later.');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ error: "Invalid email or password" });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.json({ error: "Invalid email or password" });
        }

        const token = generateJWTToken(user);

        // Send token via email
        await sendLoginTokenEmail(email, token);

        res.status(200).send('Login token has been sent to your email.');
    } catch (error) {
        console.error("An error occurred while logging in:", error);
        res.json({ error: "An error occurred while logging in" });
    }
});

app.get('/profile', async (req, res) => {
    const token = req.query.token;

    if (!token) {
        return res.json({ error: "Access denied. No token provided." });
    }

    try {
        const decoded = jwt.verify(token, jwt_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            return res.json({ error: "User not found" });
        }
        res.render('profile', { user });
    } catch (error) {
        console.error("Error fetching profile:", error);
        res.json({ error: "An error occurred while fetching the profile" });
    }
});

app.post('/logout', (req, res) => {
    res.redirect('/login');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

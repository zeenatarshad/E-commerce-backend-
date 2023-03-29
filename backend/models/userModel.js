const mongoose = require("mongoose");
const validator = require("validator");

const userSchema = new mongoose.Schema({

    name:{
        type: String,
        required: [true, "Please enter your name"],
        maxLength: [30, "Name cannot exceed 30 characters"],
        minLength: [4, "Name should be greater than 4 characters"]
    },
    email:{
        type: String,
        required: [true, "Please enter your email"],
        unique: true,
        validate: [validator.isEmail, "Please enter a valid email id"]
    },
    password:{
        type: String,
        required: [true, "Please enter your password"],
        minLength: [8, "Password should have greater than 8 characters"],
        select: false
    },
    avatar:{
        public_id:{
            type: String,
            required: true,
        },
        url:{
            type: String,
            required: true,
        }
    },
    role:{
        type: String,
        default: "user",
    },

    resetPasswordToken: String,
    resetPasswordExpire: Date
});

module.exports = mongoose.model("User",userSchema);
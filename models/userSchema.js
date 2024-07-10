import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcrypt";
import Jwt  from "jsonwebtoken";

const useSchema = new mongoose.Schema({
    name:{
        type:String,
        required : [true, "Please Provide Your name"],
        minLength: [3, "Name must contain at least 3 characters"],
        maxLength: [30, "Name cannot exceed 30 characters"],
    },
    email:{
        type:String,
        required: [true, "Please Provide your email"],
        validate:[validator.isEmail, "Please provide a valid email"],
    },
    phone:{
        type: Number,
        required: [true, "please provide your phone number,"],
    },
    password:{
        type:String,
        required:[true, "please provide your password"] ,
        minLength: [8, "Password must contain at least 8 characters"],
        maxLength: [32, "password cannot exced 32 characters!"],
        select:false,
    },
    role:{
        type: String,
        required: [true, "please provide your role"],
        enum: ["Job Seeker", "Employer"],
    },
    createAt:{
        type: Date,
        default: Date.now,
    },
});

// HASING THE PASSWORD
useSchema.pre("save", async function (next){
    if(!this.isModified("password")){
        next();
    }
    this.password = await bcrypt.hash(this.password, 10);
});

// COMPARING PASSWORD
useSchema.methods.comparePassword = async function (enteredPassword){
    return await bcrypt.compare(enteredPassword, this.password);
};

// GENERATING A JWT TOKEN FOR AUTHORIZATION
useSchema.methods.getJWTToken = function(){
    return Jwt.sign({id: this._id}, process.env.JWT_SECRET_KEY,{
        expiresIn: process.env.JWT_EXPIRE,
    });
};

export const User = mongoose.model("User", useSchema);
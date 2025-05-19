import sendEmail from '../config/sendemail.js'
import UserModel from '../models/user.model.js'
import bcryptjs from 'bcryptjs'
import verifyEmailTemplate from '../utils/verifyemailTemplate.js'
import generateAccessToken from '../utils/generateAccessToken.js'
import generateRefreshToken from '../utils/generateRefreshToken.js'
import uploadImageCloudinary from '../utils/uploadImageCloudinary.js'
import forgetPasswordTemplate from '../utils/forgetPasswordTemplate.js'
import generateOTP from '../utils/generateOTP.js'
import jwt from 'jsonwebtoken'

// Register
export async function registerUserController(request,response){
    try {
        const { name, email , password } = request.body

        if(!name || !email || !password){
            return response.status(400).json({
                message : "provide name, email, password",     
                error : true,
                success : false
            })
        }

        const user = await UserModel.findOne({ email })

        if(user){
            return response.json({
                message : "Already register email",
                error : true,
                success : false
            })
        }

        const salt = await bcryptjs.genSalt(10)
        const hashPassword = await bcryptjs.hash(password,salt)

        const payload = {
            name,
            email,
            password : hashPassword
        }

        const newUser = new UserModel(payload)
        const save = await newUser.save()


        const VerifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`

        const verifyEmail = await sendEmail({
            sendTo : email,
            subject : "Verify email from blinkit",
            html : verifyEmailTemplate({
                name,
                url : VerifyEmailUrl
            })
        });

        if (!verifyEmail) {
            return response.status(500).json({
            message: "Failed to send verification email",
            error: true,
            success: false
            });
        }

        return response.json({
            message : "User register successfully",
            error : false,
            success : true,
            data : save
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// Verify Email
export async function verifyEmailController(req , res){
    try{
        const { code } = req.body

        const user = await UserModel.findOne({ _id : code});

        if(!user)
        {
            return res.status(400).json({
                message : "Invalid code",
                error : true,
                success : false
            })
        }

        const updateUser = await UserModel.findOne({ _id : code} , {
            verify_email : true
        });

        return res.json({
            message : "Email Verifyed",
            error : false,
            success : true
        });
    }
    catch(error)
    {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// Login
export async function loginController(req , res){
    try{
        const { email , password } = req.body;

        if(!email || !password)
        {
            return res.status(400).json({
                message : "Provide credentials",
                error : true,
                success : false
            })
        }

        const user = await UserModel.findOne({ email });

        if(!user)
        {
            return res.status(400).json({
                message : "Invalid User",
                error : true,
                status : false
            });
        }

        if(user.status !== "Active")
        {
            return res.status(400).json({
                message : "User is not active",
                error : true,
                success : false
            });
        }

        const isMatch = await bcryptjs.compare(password , user.password);

        if(!isMatch)
        {
            return res.status(400).json({
                message : "Invalid Credentials",
                error : true,
                success : false
            });
        }

        const accessToken = await generateAccessToken(user._id);
        const refreshToken = await generateRefreshToken(user._id);

        const cookieOptions = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }

        res.cookie("accessToken" , accessToken , cookieOptions);
        res.cookie("refreshToken" , refreshToken , cookieOptions);

        return res.json({
            message : "Login Successfully",
            error : false,
            success : true,
            data : {
                accessToken,
                refreshToken
            }
        });
    }
    catch(error)
    {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// LogOut
export async function logoutController(req , res)
{
    try{

        const userid = req.userId;

        const cookieOptions = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }

        res.clearCookie("accessToken" , cookieOptions);
        res.clearCookie("refreshToken" , cookieOptions);

        const removeRefreshToken = await UserModel.findByIdAndUpdate(userid , {
            refresh_token : ""
        })

        return res.json({
            message : "Logout Successfully",
            error : false,
            success : true
        })
    }
    catch(error)
    {
        res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        });
    }
}

// upload user avtar
export async function uploadAvtar(req , res){
    try {
        const userId = req.userId;
        const image = req.file;

        const upload = await uploadImageCloudinary(image);

        const updateUser = await UserModel.findByIdAndUpdate(userId , {
            avatar : upload?.url
        })
        return res.json({
            message : "upload profile",
            data : {
                _id : userId,
                avatar : upload?.url
            }
        })
    } 
    catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

// update user details
export async function updateUserDetails(req , res){
    try {
        const userId = req.userId;
        
        const { name , email , password , mobile } = req.body;

        let hashPassword = " ";

        if(password)
        {
            const salt = await bcryptjs.genSalt(10);
            hashPassword = await bcryptjs.hash(password , salt);
        }

        const updateUser = await UserModel.updateOne({_id : userId}, {
            ...( name && { name  : name }),
            ...(email && { email : email }),
            ...(mobile && { mobile : mobile }),
            ...(password && { password : hashPassword }),
        });

        return res.json({
            message : "User details updated",
            error : false,
            success : true,
            data : updateUser
        });
    } 
    catch (error) {
        return res.satatus(500).json({
            message : error.message || error,
            error : true,
            success : false
        })    
    }
}

// Forget Password
export async function forgetPasswordController(req , res){
    try {
        const { email } = req.body;

        const user = await UserModel.findOne({ email });

        if(!user)
        {
            return res.status(400).json({
                message : "UserNot Found",
                error : true,
                 success : false
            });
        }

        const OTP = generateOTP();
        const expireTime = new Date() + 60 * 60 * 1000; // 1 hr

        const update = await UserModel.findByIdAndUpdate(user._id , {
            forgot_password_otp : OTP,
            forgot_password_expire : new Date(expireTime).toISOString()
        });

        await sendEmail({
            sendTo : email,
            subject : "Forget Password from Blinkit",
            html : forgetPasswordTemplate({
                name : user.name,
                otp : OTP
            })
        })

        return res.json({
            message : "Check ur email",
            error : false,
            success : true
        });
    } 
    catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error: true,
            success : false
        }) 
    }
}

// verigy forget password
export async function verifyForgetPasswordOTP(req , res){
    try {
        const { email , otp } = req.body;

        const user = await UserModel.findOne({ email });

        if(!email || !otp)
        {
            return res.status(400).json({
                message : "Invalid email or otp",
                error : true,
                success : false
            });
        }

        if(!user)
        {
            return res.status(400).json({
                message : "Email not available",
                error : true,
                success : false
            });
        }

        const currTime = new Date();

        if(user.forgot_password_expire > currTime)
        {
            return res.status(400).json({
                message : "OTP Expired",
                error : true,
                success : false
            });
        }

        if(otp !== user.forgot_password_otp)
        {
            return res.status(400).json({
                message : "Invalid otp",
                error : true,
                success : false
            });
        }

        // otp not expired and otp === user.forgot_password_otp

        return res.json({
            message : "OTP verified successfully",
            error : false,
            success : true
        });
    } 
    catch (error) 
    {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })    
    }
}

// reset passowrd
export async function resetPassword(req , res){
    try {
        const { email , newPassword , confirmPassword } = req.body;

        if(!email || !newPassword || !confirmPassword)
        {
            return res.status(400).json({
                message : "provide email, new password and confirm password",
                error : true,
                success : false
            });
        }

        const user = await UserModel.findOne({ email });

        if(!user)
        {
            return res.status(400).json({
                message : "Email is not available",
                error : true,
                success : false
            });
        }

        if(newPassword !== confirmPassword)
        {
            return res.status(400).json({
                message : "Password not matched",
                error : true,
                success : false
            });
        }

        const salt = await bcryptjs.genSalt(10);
        const hashPassword = await bcryptjs.hash(newPassword , salt);

        const update = await UserModel.findOneAndUpdate( user._id , {
            password : hashPassword
        });

        return res.json({
            message : "Password reset successfully",
            error : false,
            success : true
        });
    } 
    catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        });    
    }
} 

// refresh Token Controller
export async function refreshTokenController(req , res){
    try {
        const refreshToken = req.cookies.refreshToken || req.header?.authorization?.split(" ")[1];

        if(!refreshToken)
        {
            return res.status(400).json({
                message : "Unauthorized Access",
                error : true,
                success : false
            });
        }

        const verifyToken = await jwt.verify(refreshToken , process.env.SECRET_KEY_REFRESH_TOKEN);
        
        if(!verifyToken)
        {
            return res.status(400).json({
                message : "Refresh token expired",
                error : true,
                success : false
            });
        }

        console.log("verifyToken" , verifyToken);
        const userId = verifyToken?._id;

        const newAccessToken = await generateAccessToken(userId);

        const cookieOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }

        res.cookie('accessToken' , newAccessToken , cookieOption);

        return res.json({
            message : "New AccessToken generated",
            error : false,
            success : true,
            data : {
                accessToken : newAccessToken
            }
        })  

    } 
    catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        });    
    }
}
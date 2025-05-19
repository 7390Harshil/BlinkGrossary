const forgetPasswordTemplate = ({ name , otp })=>{
    return `
    <div> 
    <p> Dear ${name} , </p>
    <p> You are requested to resest your Password. 
    Please use the following otp code to reset your password. </p>
    <div style = "background : yellow ; font-size : 20px ; padding : 20px; text-align : center ; font-weight : 800;"> OTP : ${otp} </div>
    <p>This OTP is valid for only 1 Hour only. Enter this OTP in the blinkit website
    to proceed with resetting your password. </p>
    <br/>
    </br>
    <p>Thanks</p>
    <p> Blinkit </p>
    </div>`
}

export default forgetPasswordTemplate;
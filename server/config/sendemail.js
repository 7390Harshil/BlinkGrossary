import { Resend } from 'resend';
import dotenv from 'dotenv';
dotenv.config();

if (!process.env.RESEND_API) {
    console.log("Provide RESEND_API in the .env file");
}

const resend = new Resend(process.env.RESEND_API);

const sendEmail = async ({ sendTo, subject, html }) => {
    try {
        const data = await resend.emails.send({
            from: 'Blinkit <onboarding@resend.dev>',
            to: sendTo,
            subject,
            html,
        });
        console.log("Email sent successfully:", data);
        return data;
    } catch (error) {
        console.error("Exception while sending email:", error);
        return null;
    }
};

export default sendEmail;
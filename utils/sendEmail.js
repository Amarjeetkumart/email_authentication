const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
// Load environment variables
dotenv.config();
// Create a new transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});
// Send email function
async function sendEmail(to, subject, text) {
  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to,
    subject,
    text,
  });
}
// Export the sendEmail function
module.exports = sendEmail;

import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
    secure:true,
    host: "smtp.gmail.com",
    port: 465,
    auth: {
        user: "vishwesh.reddy2001@gmail.com",
        pass: "qwlw bets geql kwrb"
    }
});

function sendMail(to,sub,msg){
    transporter.sendMail({
        to:to,
        subject:sub,
        html:msg
    });
    console.log("email sent");
}

sendMail("vigneshsmart1103@gmail.com","about vignesh","istaad ismart vignesh");